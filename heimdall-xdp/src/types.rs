//! Shared types between kernel and userspace

use aya::Pod;
use std::net::Ipv4Addr;

// ============================================================================
// Detection Events (Ring Buffer)
// ============================================================================

pub const EVENT_TYPE_SYN_FLOOD: u8 = 1;
pub const EVENT_TYPE_PORT_SCAN: u8 = 2;
pub const EVENT_TYPE_BLOCKED: u8 = 3;
pub const EVENT_TYPE_UDP_FLOOD: u8 = 4;
pub const EVENT_TYPE_ICMP_FLOOD: u8 = 5;
pub const EVENT_TYPE_GEOIP_BLOCKED: u8 = 6;
pub const EVENT_TYPE_ALLOWLIST_DENIED: u8 = 7;

// Configuration flags
pub const CFG_GATEWAY_MODE: u32 = 0;
pub const CFG_ALLOWLIST_ENABLED: u32 = 1;
pub const CFG_GEOIP_ENABLED: u32 = 2;
pub const CFG_UDP_RATELIMIT: u32 = 3;
pub const CFG_ICMP_RATELIMIT: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DetectionEvent {
    pub src_ip: u32,
    pub event_type: u8,
    pub reserved: u8,
    pub dst_port: u16,
    pub timestamp: u64,
    pub count: u32,
}

unsafe impl Pod for DetectionEvent {}

impl DetectionEvent {
    pub fn src_ip_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.src_ip.to_be())
    }
    
    pub fn event_type_name(&self) -> &'static str {
        match self.event_type {
            EVENT_TYPE_SYN_FLOOD => "SYN_FLOOD",
            EVENT_TYPE_PORT_SCAN => "PORT_SCAN",
            EVENT_TYPE_BLOCKED => "BLOCKED",
            EVENT_TYPE_UDP_FLOOD => "UDP_FLOOD",
            EVENT_TYPE_ICMP_FLOOD => "ICMP_FLOOD",
            EVENT_TYPE_GEOIP_BLOCKED => "GEOIP_BLOCKED",
            EVENT_TYPE_ALLOWLIST_DENIED => "ALLOWLIST_DENIED",
            _ => "UNKNOWN",
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
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

unsafe impl Pod for Stats {}

// ============================================================================
// Protection State (Maps)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    pub last_update: u64,
    pub tokens: u32,
    pub _pad: u32,
}

unsafe impl Pod for TokenBucket {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PortScanState {
    pub window_start: u64,
    pub conn_count: u32,
    pub alerted: u32,
}

unsafe impl Pod for PortScanState {}
