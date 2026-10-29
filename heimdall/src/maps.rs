//! eBPF Map Management
//! Provides safe Rust API to populate and manage eBPF maps

use anyhow::{Context, Result};
use aya::maps::{HashMap, Array, PerCpuArray};
use aya::Ebpf;
use std::net::IpAddr;
use tracing::{info, warn};

/// Stats structure matching eBPF (must match heimdall-xdp-ebpf/src/main.rs)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub total_packets: u64,
    pub blocked_packets: u64,
    pub passed_packets: u64,
    pub ipv4_packets: u64,
    pub ipv6_packets: u64,
    pub gateway_fast_path: u64,
    pub syn_rate_limited: u64,
    pub udp_rate_limited: u64,
    pub icmp_rate_limited: u64,
    pub port_scan_detected: u64,
    pub geoip_blocked: u64,
    pub allowlist_denied: u64,
}

// SAFETY: Stats is a plain struct with only u64 fields, no padding issues
unsafe impl aya::Pod for Stats {}

pub struct MapManager {
    pub blocklist_v4: HashMap<aya::maps::MapData, u32, u64>,
    pub config: Array<aya::maps::MapData, u32>,
    pub gateway_ports: HashMap<aya::maps::MapData, u16, u8>,
    pub allowlist_v4: HashMap<aya::maps::MapData, u32, u8>,
    pub allowlist_ports: HashMap<aya::maps::MapData, u16, u8>,
    pub blocked_countries: HashMap<aya::maps::MapData, u8, u8>,
    pub geoip_v4: HashMap<aya::maps::MapData, u32, u8>,
    pub stats: PerCpuArray<aya::maps::MapData, Stats>,
}

// Configuration flags (must match eBPF)
pub const CFG_GATEWAY_MODE: u32 = 0;
pub const CFG_ALLOWLIST_ENABLED: u32 = 1;
pub const CFG_GEOIP_ENABLED: u32 = 2;
pub const CFG_UDP_RATELIMIT: u32 = 3;
pub const CFG_ICMP_RATELIMIT: u32 = 4;

impl MapManager {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self> {
        let blocklist_v4 = HashMap::try_from(
            ebpf.take_map("BLOCKLIST_V4")
                .context("BLOCKLIST_V4 map not found")?
        )?;
        
        let config = Array::try_from(
            ebpf.take_map("CONFIG")
                .context("CONFIG map not found")?
        )?;
        
        let gateway_ports = HashMap::try_from(
            ebpf.take_map("GATEWAY_PORTS")
                .context("GATEWAY_PORTS map not found")?
        )?;
        
        let allowlist_v4 = HashMap::try_from(
            ebpf.take_map("ALLOWLIST_V4")
                .context("ALLOWLIST_V4 map not found")?
        )?;
        
        let allowlist_ports = HashMap::try_from(
            ebpf.take_map("ALLOWLIST_PORTS")
                .context("ALLOWLIST_PORTS map not found")?
        )?;
        
        let blocked_countries = HashMap::try_from(
            ebpf.take_map("BLOCKED_COUNTRIES")
                .context("BLOCKED_COUNTRIES map not found")?
        )?;
        
        let geoip_v4 = HashMap::try_from(
            ebpf.take_map("GEOIP_V4")
                .context("GEOIP_V4 map not found")?
        )?;
        
        let stats = PerCpuArray::try_from(
            ebpf.take_map("STATS")
                .context("STATS map not found")?
        )?;
        
        Ok(Self {
            blocklist_v4,
            config,
            gateway_ports,
            allowlist_v4,
            allowlist_ports,
            blocked_countries,
            geoip_v4,
            stats,
        })
    }
    
    /// Enable gateway mode
    pub fn enable_gateway_mode(&mut self) -> Result<()> {
        self.config.set(CFG_GATEWAY_MODE, 1, 0)?;
        info!("✅ Gateway mode enabled");
        Ok(())
    }
    
    /// Add ports to gateway fast-path
    pub fn add_gateway_ports(&mut self, ports: &[u16]) -> Result<()> {
        for port in ports {
            self.gateway_ports.insert(port, 1, 0)?;
        }
        info!("✅ Gateway ports configured: {:?}", ports);
        Ok(())
    }
    
    /// Enable UDP rate limiting
    pub fn enable_udp_ratelimit(&mut self) -> Result<()> {
        self.config.set(CFG_UDP_RATELIMIT, 1, 0)?;
        info!("✅ UDP rate limiting enabled");
        Ok(())
    }
    
    /// Enable ICMP rate limiting
    pub fn enable_icmp_ratelimit(&mut self) -> Result<()> {
        self.config.set(CFG_ICMP_RATELIMIT, 1, 0)?;
        info!("✅ ICMP rate limiting enabled");
        Ok(())
    }
    
    /// Enable allowlist mode
    pub fn enable_allowlist(&mut self) -> Result<()> {
        self.config.set(CFG_ALLOWLIST_ENABLED, 1, 0)?;
        info!("✅ Allowlist mode enabled");
        Ok(())
    }
    
    /// Add ports that require allowlist check
    pub fn add_allowlist_ports(&mut self, ports: &[u16]) -> Result<()> {
        for port in ports {
            self.allowlist_ports.insert(port, 1, 0)?;
        }
        info!("✅ Allowlist ports configured: {:?}", ports);
        Ok(())
    }
    
    /// Add IP to allowlist
    pub fn add_allowlist_ip(&mut self, ip: IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_u32 = u32::from_be_bytes(ipv4.octets());
                self.allowlist_v4.insert(ip_u32, 1, 0)?;
                info!("✅ Added {} to allowlist", ip);
            }
            IpAddr::V6(_) => {
                warn!("IPv6 allowlist not yet implemented");
            }
        }
        Ok(())
    }
    
    /// Enable GeoIP blocking (P2)
    pub fn enable_geoip(&mut self) -> Result<()> {
        self.config.set(CFG_GEOIP_ENABLED, 1, 0)?;
        info!("✅ GeoIP blocking enabled");
        Ok(())
    }
    
    /// Block specific country codes (P2)
    pub fn block_countries(&mut self, country_codes: &[String]) -> Result<()> {
        for code in country_codes {
            if code.len() == 2 {
                // Convert 2-letter country code to u8 for eBPF map.
                // NOTE: this keys on first letter only, so codes sharing a first
                // letter (e.g. CN/CA) collide and block together -- see README
                // Known Limitations. Fine for the manual-list use case tested so
                // far; would need a real hash/lookup table before this can be
                // trusted for country pairs that share a first letter.
                let country_id = code.as_bytes()[0];
                self.blocked_countries.insert(country_id, 1, 0)?;
            }
        }
        info!("✅ Blocked countries configured: {:?}", country_codes);
        Ok(())
    }
    
    /// Load GeoIP database and populate eBPF map (P2)
    pub fn load_geoip_db(&mut self, _db_path: &std::path::Path) -> Result<()> {
        // TODO: Implement MaxMind GeoLite2 database loading
        // For now, this is a placeholder for future implementation
        warn!("⚠️ GeoIP database loading not yet implemented");
        warn!("⚠️ Will use country blocking with manual IP->country mapping in future");
        Ok(())
    }
    
    /// Read current stats from eBPF map
    pub fn read_stats(&self) -> Result<Stats> {
        // PerCpuArray stores per-CPU values, we need to aggregate
        let per_cpu_stats = self.stats.get(&0, 0)?;
        
        // Aggregate across all CPUs (for single-CPU, just return the value)
        let mut aggregated = Stats::default();
        for cpu_stats in per_cpu_stats.iter() {
            aggregated.total_packets = aggregated.total_packets.wrapping_add(cpu_stats.total_packets);
            aggregated.blocked_packets = aggregated.blocked_packets.wrapping_add(cpu_stats.blocked_packets);
            aggregated.passed_packets = aggregated.passed_packets.wrapping_add(cpu_stats.passed_packets);
            aggregated.ipv4_packets = aggregated.ipv4_packets.wrapping_add(cpu_stats.ipv4_packets);
            aggregated.ipv6_packets = aggregated.ipv6_packets.wrapping_add(cpu_stats.ipv6_packets);
            aggregated.gateway_fast_path = aggregated.gateway_fast_path.wrapping_add(cpu_stats.gateway_fast_path);
            aggregated.syn_rate_limited = aggregated.syn_rate_limited.wrapping_add(cpu_stats.syn_rate_limited);
            aggregated.udp_rate_limited = aggregated.udp_rate_limited.wrapping_add(cpu_stats.udp_rate_limited);
            aggregated.icmp_rate_limited = aggregated.icmp_rate_limited.wrapping_add(cpu_stats.icmp_rate_limited);
            aggregated.port_scan_detected = aggregated.port_scan_detected.wrapping_add(cpu_stats.port_scan_detected);
            aggregated.geoip_blocked = aggregated.geoip_blocked.wrapping_add(cpu_stats.geoip_blocked);
            aggregated.allowlist_denied = aggregated.allowlist_denied.wrapping_add(cpu_stats.allowlist_denied);
        }
        
        Ok(aggregated)
    }
    
    /// Block IP immediately
    pub fn block_ip(&mut self, ip: IpAddr, ttl: u64) -> Result<()> {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_u32 = u32::from_be_bytes(ipv4.octets());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let expires = now + ttl;
                self.blocklist_v4.insert(ip_u32, expires, 0)?;
                info!("🔨 Blocked {} (TTL: {}s)", ip, ttl);
            }
            IpAddr::V6(_) => {
                warn!("IPv6 blocking via API not yet implemented");
            }
        }
        Ok(())
    }
}
