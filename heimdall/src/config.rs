//! HEIMDALL Configuration

use std::path::PathBuf;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub mode: String,
    pub ebpf_path: PathBuf,
    pub svalinn_url: Option<String>,
    pub api_key: Option<String>,
    pub sync_interval_secs: u64,
    pub min_score: u64,
    pub autoblock: bool,
    pub monitor_only: bool,
    pub ban_ttl_secs: u64,
    pub prom_addr: String,
    pub failsafe_enabled: bool,
    pub failsafe_threshold: f64,
    /// Path to secondary XDP program to chain (e.g., MIMIR)
    pub chain_ebpf: Option<PathBuf>,
    /// P1: Gateway mode (fast-path for specified ports)
    pub gateway_mode: bool,
    pub gateway_ports: Vec<u16>,
    /// P1: Enhanced rate limiting
    pub enable_udp_ratelimit: bool,
    pub enable_icmp_ratelimit: bool,
    /// P2: Allowlist mode
    pub enable_allowlist: bool,
    pub allowlist_ports: Vec<u16>,
    pub allowlist_ips: Vec<IpAddr>,
    /// P2: GeoIP blocking
    pub enable_geoip: bool,
    pub blocked_countries: Vec<String>,
    pub geoip_db_path: Option<PathBuf>,
}
