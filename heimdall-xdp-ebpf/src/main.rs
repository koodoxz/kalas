//! HEIMDALL XDP eBPF Program
//! L3/L4 Intelligent Firewall - Kernel Space

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};

// Define local copies of shared structs for eBPF compliance
// In a refined Aya setup, we'd use a shared common crate with [no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DetectionEvent {
    pub src_ip: u32,
    pub event_type: u8,
    pub reserved: u8,
    pub dst_port: u16,
    pub timestamp: u64,
    pub count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Stats {
    pub total_packets: u64,
    pub blocked_packets: u64,
    pub passed_packets: u64,
    pub ipv4_packets: u64,
    pub ipv6_packets: u64,
    pub syn_rate_limited: u64,
    pub port_scan_detected: u64,
    // P1: New counters
    pub udp_rate_limited: u64,
    pub icmp_rate_limited: u64,
    pub gateway_fast_path: u64,
    // P2: New counters
    pub geoip_blocked: u64,
    pub allowlist_denied: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenBucket {
    pub last_update: u64,
    pub tokens: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PortScanState {
    pub window_start: u64,
    pub conn_count: u32,
    pub alerted: u32,
}

pub const EVENT_TYPE_SYN_FLOOD: u8 = 1;
pub const EVENT_TYPE_PORT_SCAN: u8 = 2;
pub const EVENT_TYPE_BLOCKED: u8 = 3;
pub const EVENT_TYPE_UDP_FLOOD: u8 = 4;
pub const EVENT_TYPE_ICMP_FLOOD: u8 = 5;
pub const EVENT_TYPE_GEOIP_BLOCKED: u8 = 6;
pub const EVENT_TYPE_ALLOWLIST_DENIED: u8 = 7;

// Rate limiting constants
const SYN_RATE_LIMIT: u32 = 100;
const SYN_BURST: u32 = 200;
const UDP_RATE_LIMIT: u32 = 500;      // P1: UDP packets/s per IP
const UDP_BURST: u32 = 1000;
const ICMP_RATE_LIMIT: u32 = 10;      // P1: ICMP packets/s per IP
const ICMP_BURST: u32 = 20;
const PORT_SCAN_THRESHOLD: u32 = 20;
const PORT_SCAN_WINDOW_NS: u64 = 10_000_000_000;

// Configuration flags (set via userspace)
const CFG_GATEWAY_MODE: u32 = 0;      // P1: Smart passthrough for gateway servers
const CFG_ALLOWLIST_ENABLED: u32 = 1; // P2: Allowlist mode
const CFG_GEOIP_ENABLED: u32 = 2;     // P2: GeoIP blocking
const CFG_UDP_RATELIMIT: u32 = 3;     // P1: UDP rate limiting
const CFG_ICMP_RATELIMIT: u32 = 4;    // P1: ICMP rate limiting

#[map]
static BLOCKLIST_V4: LruHashMap<u32, u64> = LruHashMap::with_max_entries(100_000, 0);

#[map]
static BLOCKLIST_V6: LruHashMap<[u8; 16], u64> = LruHashMap::with_max_entries(50_000, 0);

#[map]
static STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static SYN_RATE_LIMIT_MAP: LruHashMap<u32, TokenBucket> = LruHashMap::with_max_entries(100_000, 0);

#[map]
static PORT_SCAN_MAP: LruHashMap<u32, PortScanState> = LruHashMap::with_max_entries(50_000, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// P1: UDP rate limiting map
#[map]
static UDP_RATE_LIMIT_MAP: LruHashMap<u32, TokenBucket> = LruHashMap::with_max_entries(100_000, 0);

// P1: ICMP rate limiting map
#[map]
static ICMP_RATE_LIMIT_MAP: LruHashMap<u32, TokenBucket> = LruHashMap::with_max_entries(50_000, 0);

// P1: Configuration map (gateway mode, feature flags)
#[map]
static CONFIG: aya_ebpf::maps::Array<u32> = aya_ebpf::maps::Array::with_max_entries(16, 0);

// P1: Gateway ports (fast-path for these ports in gateway mode)
#[map]
static GATEWAY_PORTS: LruHashMap<u16, u8> = LruHashMap::with_max_entries(64, 0);

// P2: Allowlist IPv4
#[map]
static ALLOWLIST_V4: LruHashMap<u32, u8> = LruHashMap::with_max_entries(10_000, 0);

// P2: Allowlist IPv6
#[map]
static ALLOWLIST_V6: LruHashMap<[u8; 16], u8> = LruHashMap::with_max_entries(5_000, 0);

// P2: Ports that require allowlist check
#[map]
static ALLOWLIST_PORTS: LruHashMap<u16, u8> = LruHashMap::with_max_entries(64, 0);

// P2: GeoIP database (IP prefix -> country code)
#[map]
static GEOIP_V4: LruHashMap<u32, u8> = LruHashMap::with_max_entries(500_000, 0);

// P2: Blocked countries
#[map]
static BLOCKED_COUNTRIES: LruHashMap<u8, u8> = LruHashMap::with_max_entries(256, 0);

/// Program array for tail-calling to chained XDP programs (e.g., MIMIR DNS filter)
/// Index 0: Next XDP program (if any)
#[map]
static JUMP_TABLE: aya_ebpf::maps::ProgramArray = aya_ebpf::maps::ProgramArray::with_max_entries(4, 0);

#[inline(always)]
fn get_ktime_ns() -> u64 {
    unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() }
}

#[inline(always)]
fn emit_event(src_ip: u32, event_type: u8, dst_port: u16, count: u32) {
    if let Some(mut buf) = EVENTS.reserve::<DetectionEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).src_ip = src_ip;
            (*event).event_type = event_type;
            (*event).reserved = 0;
            (*event).dst_port = dst_port;
            (*event).timestamp = get_ktime_ns();
            (*event).count = count;
        }
        buf.submit(0);
    }
}

#[inline(always)]
fn check_syn_rate_limit(src_ip: u32, stats: &mut Stats) -> bool {
    let now = get_ktime_ns();
    
    if let Some(bucket) = unsafe { SYN_RATE_LIMIT_MAP.get(&src_ip) } {
        let mut bucket = *bucket;
        let elapsed_ns = now.saturating_sub(bucket.last_update);
        let refill = ((elapsed_ns as u64 * SYN_RATE_LIMIT as u64) / 1_000_000_000) as u32;
        
        if refill > 0 {
            bucket.tokens = (bucket.tokens + refill).min(SYN_BURST);
            bucket.last_update = now;
        }
        
        if bucket.tokens >= 1 {
            bucket.tokens -= 1;
            let _ = SYN_RATE_LIMIT_MAP.insert(&src_ip, &bucket, 0);
            return false;
        }
        
        stats.syn_rate_limited = stats.syn_rate_limited.wrapping_add(1);
        emit_event(src_ip, EVENT_TYPE_SYN_FLOOD, 0, bucket.tokens);
        return true;
    }
    
    let new_bucket = TokenBucket {
        last_update: now,
        tokens: SYN_BURST - 1,
        _pad: 0,
    };
    let _ = SYN_RATE_LIMIT_MAP.insert(&src_ip, &new_bucket, 0);
    false
}

#[inline(always)]
fn check_port_scan(src_ip: u32, dst_port: u16, stats: &mut Stats) -> bool {
    let now = get_ktime_ns();
    
    if let Some(state) = unsafe { PORT_SCAN_MAP.get(&src_ip) } {
        let mut state = *state;
        
        if now.saturating_sub(state.window_start) > PORT_SCAN_WINDOW_NS {
            state.window_start = now;
            state.conn_count = 1;
            state.alerted = 0;
            let _ = PORT_SCAN_MAP.insert(&src_ip, &state, 0);
            return false;
        }
        
        state.conn_count += 1;
        
        if state.conn_count >= PORT_SCAN_THRESHOLD && state.alerted == 0 {
            state.alerted = 1;
            stats.port_scan_detected = stats.port_scan_detected.wrapping_add(1);
            emit_event(src_ip, EVENT_TYPE_PORT_SCAN, dst_port, state.conn_count);
            let _ = PORT_SCAN_MAP.insert(&src_ip, &state, 0);
            return true;
        }
        
        let _ = PORT_SCAN_MAP.insert(&src_ip, &state, 0);
        return false;
    }
    
    let new_state = PortScanState {
        window_start: now,
        conn_count: 1,
        alerted: 0,
    };
    let _ = PORT_SCAN_MAP.insert(&src_ip, &new_state, 0);
    false
}

// P1: UDP rate limiting
#[inline(always)]
fn check_udp_rate_limit(src_ip: u32) -> bool {
    let now = get_ktime_ns();
    
    if let Some(bucket) = unsafe { UDP_RATE_LIMIT_MAP.get(&src_ip) } {
        let mut bucket = *bucket;
        let elapsed_ns = now.saturating_sub(bucket.last_update);
        let refill = ((elapsed_ns as u64 * UDP_RATE_LIMIT as u64) / 1_000_000_000) as u32;
        
        if refill > 0 {
            bucket.tokens = (bucket.tokens + refill).min(UDP_BURST);
            bucket.last_update = now;
        }
        
        if bucket.tokens >= 1 {
            bucket.tokens -= 1;
            let _ = UDP_RATE_LIMIT_MAP.insert(&src_ip, &bucket, 0);
            return false;
        }
        
        emit_event(src_ip, EVENT_TYPE_UDP_FLOOD, 0, bucket.tokens);
        return true; // Caller updates stats.udp_rate_limited
    }
    
    let new_bucket = TokenBucket {
        last_update: now,
        tokens: UDP_BURST - 1,
        _pad: 0,
    };
    let _ = UDP_RATE_LIMIT_MAP.insert(&src_ip, &new_bucket, 0);
    false
}

// P1: ICMP rate limiting
#[inline(always)]
fn check_icmp_rate_limit(src_ip: u32) -> bool {
    let now = get_ktime_ns();
    
    if let Some(bucket) = unsafe { ICMP_RATE_LIMIT_MAP.get(&src_ip) } {
        let mut bucket = *bucket;
        let elapsed_ns = now.saturating_sub(bucket.last_update);
        let refill = ((elapsed_ns as u64 * ICMP_RATE_LIMIT as u64) / 1_000_000_000) as u32;
        
        if refill > 0 {
            bucket.tokens = (bucket.tokens + refill).min(ICMP_BURST);
            bucket.last_update = now;
        }
        
        if bucket.tokens >= 1 {
            bucket.tokens -= 1;
            let _ = ICMP_RATE_LIMIT_MAP.insert(&src_ip, &bucket, 0);
            return false;
        }
        
        emit_event(src_ip, EVENT_TYPE_ICMP_FLOOD, 0, bucket.tokens);
        return true; // Caller updates stats.icmp_rate_limited
    }
    
    let new_bucket = TokenBucket {
        last_update: now,
        tokens: ICMP_BURST - 1,
        _pad: 0,
    };
    let _ = ICMP_RATE_LIMIT_MAP.insert(&src_ip, &new_bucket, 0);
    false
}

// P1: Check if config flag is enabled
#[inline(always)]
fn is_config_enabled(flag: u32) -> bool {
    if let Some(val) = unsafe { CONFIG.get(flag) } {
        return *val != 0;
    }
    false
}

// P1: Check if port is a gateway port (fast-path)
#[inline(always)]
fn is_gateway_port(port: u16) -> bool {
    unsafe { GATEWAY_PORTS.get(&port).is_some() }
}

// P2: Check allowlist for IPv4
#[inline(always)]
fn check_allowlist_v4(src_ip: u32, dst_port: u16) -> bool {
    // If this port requires allowlist check
    if unsafe { ALLOWLIST_PORTS.get(&dst_port).is_some() } {
        // Must be in allowlist
        if unsafe { ALLOWLIST_V4.get(&src_ip).is_none() } {
            emit_event(src_ip, EVENT_TYPE_ALLOWLIST_DENIED, dst_port, 0);
            return true; // Block
        }
    }
    false // Allow
}

// P2: Check GeoIP blocking for IPv4
#[inline(always)]
fn check_geoip_v4(src_ip: u32) -> bool {
    // Lookup country code for this IP (using /24 prefix for simplicity)
    let prefix = src_ip & 0xFFFFFF00;
    if let Some(country) = unsafe { GEOIP_V4.get(&prefix) } {
        if unsafe { BLOCKED_COUNTRIES.get(country).is_some() } {
            emit_event(src_ip, EVENT_TYPE_GEOIP_BLOCKED, 0, *country as u32);
            return true; // Block
        }
    }
    false // Allow
}

#[xdp]
pub fn heimdall_xdp(ctx: XdpContext) -> u32 {
    match try_heimdall_xdp(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_heimdall_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    
    let stats = unsafe { STATS.get_ptr_mut(0).ok_or(())? };
    let stats = unsafe { &mut *stats };
    
    stats.total_packets = stats.total_packets.wrapping_add(1);
    
    // Minimum packet size check (Ethernet + IP + TCP/UDP header)
    if unsafe { data.add(54) > data_end } {
        stats.passed_packets = stats.passed_packets.wrapping_add(1);
        return Ok(xdp_action::XDP_PASS);
    }
    
    let eth_proto = unsafe { u16::from_be(*(data.add(12) as *const u16)) };
    
    // P1: Check gateway mode early
    let gateway_mode = is_config_enabled(CFG_GATEWAY_MODE);
    
    if eth_proto == 0x0800 {
        // IPv4
        stats.ipv4_packets = stats.ipv4_packets.wrapping_add(1);
        let src_ip = unsafe { *(data.add(26) as *const u32) };
        let protocol = unsafe { *data.add(23) };
        
        // Get destination port for TCP/UDP
        let dst_port = if protocol == 6 || protocol == 17 {
            unsafe { u16::from_be(*(data.add(36) as *const u16)) }
        } else {
            0
        };
        
        // P1: Gateway mode fast-path
        // If gateway mode enabled and this is a gateway port, only check blocklist
        if gateway_mode && is_gateway_port(dst_port) {
            // Fast path: only blocklist check
            if unsafe { BLOCKLIST_V4.get(&src_ip).is_some() } {
                stats.blocked_packets = stats.blocked_packets.wrapping_add(1);
                emit_event(src_ip, EVENT_TYPE_BLOCKED, dst_port, 0);
                return Ok(xdp_action::XDP_DROP);
            }
            // Skip rate limiting for gateway ports - pass immediately
            stats.gateway_fast_path = stats.gateway_fast_path.wrapping_add(1);
            stats.passed_packets = stats.passed_packets.wrapping_add(1);
            unsafe { JUMP_TABLE.tail_call(ctx, 0).ok(); }
            return Ok(xdp_action::XDP_PASS);
        }
        
        // Full processing path
        
        // Step 1: Blocklist check (always)
        if unsafe { BLOCKLIST_V4.get(&src_ip).is_some() } {
            stats.blocked_packets = stats.blocked_packets.wrapping_add(1);
            emit_event(src_ip, EVENT_TYPE_BLOCKED, dst_port, 0);
            return Ok(xdp_action::XDP_DROP);
        }
        
        // Step 2: P2 - GeoIP blocking
        if is_config_enabled(CFG_GEOIP_ENABLED) {
            if check_geoip_v4(src_ip) {
                stats.geoip_blocked = stats.geoip_blocked.wrapping_add(1);
                stats.blocked_packets = stats.blocked_packets.wrapping_add(1);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        
        // Step 3: P2 - Allowlist check (for protected ports)
        if is_config_enabled(CFG_ALLOWLIST_ENABLED) {
            if check_allowlist_v4(src_ip, dst_port) {
                stats.allowlist_denied = stats.allowlist_denied.wrapping_add(1);
                stats.blocked_packets = stats.blocked_packets.wrapping_add(1);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        
        // Step 4: Protocol-specific processing
        if protocol == 6 {
            // TCP
            let tcp_flags = unsafe { *data.add(47) };
            let syn = (tcp_flags & 0x02) != 0;
            let ack = (tcp_flags & 0x10) != 0;
            
            if syn && !ack {
                // SYN packet - rate limit check
                if check_syn_rate_limit(src_ip, stats) {
                    return Ok(xdp_action::XDP_DROP);
                }
                // Port scan detection
                check_port_scan(src_ip, dst_port, stats);
            }
        } else if protocol == 17 {
            // UDP - P1: rate limiting
            if is_config_enabled(CFG_UDP_RATELIMIT) {
                if check_udp_rate_limit(src_ip) {
                    stats.udp_rate_limited = stats.udp_rate_limited.wrapping_add(1);
                    stats.blocked_packets = stats.blocked_packets.wrapping_add(1);
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        } else if protocol == 1 {
            // ICMP - P1: rate limiting
            if is_config_enabled(CFG_ICMP_RATELIMIT) {
                if check_icmp_rate_limit(src_ip) {
                    stats.icmp_rate_limited = stats.icmp_rate_limited.wrapping_add(1);
                    stats.blocked_packets = stats.blocked_packets.wrapping_add(1);
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }
    } else if eth_proto == 0x86DD {
        // IPv6
        stats.ipv6_packets = stats.ipv6_packets.wrapping_add(1);
        let mut src_ip6 = [0u8; 16];
        for i in 0..16 {
            src_ip6[i] = unsafe { *data.add(22 + i) };
        }
        
        // Blocklist check
        if unsafe { BLOCKLIST_V6.get(&src_ip6).is_some() } {
            stats.blocked_packets = stats.blocked_packets.wrapping_add(1);
            return Ok(xdp_action::XDP_DROP);
        }
        
        // P2: Allowlist check for IPv6 (if enabled)
        if is_config_enabled(CFG_ALLOWLIST_ENABLED) {
            let protocol = unsafe { *data.add(20) }; // Next header
            // Need extra bounds check for port access (offset 54+2 = 56)
            let dst_port = if (protocol == 6 || protocol == 17) && unsafe { data.add(56) <= data_end } {
                unsafe { u16::from_be(*(data.add(54) as *const u16)) }
            } else {
                0
            };
            
            if dst_port != 0 {
                if unsafe { ALLOWLIST_PORTS.get(&dst_port).is_some() } {
                    if unsafe { ALLOWLIST_V6.get(&src_ip6).is_none() } {
                        stats.blocked_packets = stats.blocked_packets.wrapping_add(1);
                        return Ok(xdp_action::XDP_DROP);
                    }
                }
            }
        }
    }
    
    stats.passed_packets = stats.passed_packets.wrapping_add(1);
    
    // Tail-call to next program in chain (if configured)
    unsafe {
        JUMP_TABLE.tail_call(ctx, 0).ok();
    }
    
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
