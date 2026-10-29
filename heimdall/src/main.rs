//! HEIMDALL-RS: L3/L4 Intelligent Firewall
//! Part of the AEGIS Security Ecosystem
//!
//! Features:
//! - XDP-based packet filtering (100-500x faster than iptables)
//! - SVALINN Integration (global threat intelligence)
//! - SYN Flood / Port Scan detection and auto-blocking
//! - Prometheus metrics export

mod agent;
mod config;
mod svalinn;
mod metrics;
mod maps;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

const BANNER: &str = r#"
██╗  ██╗███████╗██╗███╗   ███╗██████╗  █████╗ ██╗     ██╗     
██║  ██║██╔════╝██║████╗ ████║██╔══██╗██╔══██╗██║     ██║     
███████║█████╗  ██║██╔████╔██║██║  ██║███████║██║     ██║     
██╔══██║██╔══╝  ██║██║╚██╔╝██║██║  ██║██╔══██║██║     ██║     
██║  ██║███████╗██║██║ ╚═╝ ██║██████╔╝██║  ██║███████╗███████╗
╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
          L3/L4 Intelligent Firewall - AEGIS Ecosystem
                        Rust Edition v0.1.0
"#;

#[derive(Parser, Debug)]
#[command(name = "heimdall")]
#[command(version = "0.1.0")]
#[command(about = "HEIMDALL-RS: XDP-based Intelligent Firewall")]
struct Args {
    /// Network interface to attach XDP program
    #[arg(short, long, default_value = "eth0")]
    interface: String,
    
    /// XDP mode: skb, drv, or hw
    #[arg(short, long, default_value = "skb")]
    mode: String,
    
    /// Path to eBPF object file
    #[arg(short, long, default_value = "heimdall-xdp-ebpf")]
    ebpf: PathBuf,
    
    /// SVALINN Hub URL
    #[arg(long)]
    svalinn: Option<String>,
    
    /// SVALINN API key
    #[arg(long)]
    apikey: Option<String>,
    
    /// SVALINN sync interval in seconds
    #[arg(long, default_value = "300")]
    sync_interval: u64,
    
    /// Minimum threat score to auto-block
    #[arg(long, default_value = "70")]
    min_score: u64,
    
    /// Auto-block detected attackers
    #[arg(long)]
    autoblock: bool,
    
    /// Monitor-only mode (log but don't block)
    #[arg(long)]
    monitor_only: bool,
    
    /// Ban TTL in seconds
    #[arg(long, default_value = "3600")]
    ban_ttl: u64,
    
    /// Prometheus metrics address
    #[arg(long, default_value = "0.0.0.0:9091")]
    prom_addr: String,
    
    /// Enable fail-safe (pause auto-block if block rate too high)
    #[arg(long)]
    failsafe: bool,
    
    /// Fail-safe threshold (0.0-1.0)
    #[arg(long, default_value = "0.5")]
    failsafe_threshold: f64,
    
    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    /// Chain secondary XDP program (e.g., MIMIR for DNS filtering)
    #[arg(long)]
    chain_ebpf: Option<PathBuf>,
    
    /// Enable gateway mode (fast-path for specified ports)
    #[arg(long)]
    gateway_mode: bool,
    
    /// Gateway ports (comma-separated, e.g., "53,853,8853,443")
    #[arg(long)]
    gateway_ports: Option<String>,
    
    /// Enable UDP rate limiting
    #[arg(long)]
    enable_udp_ratelimit: bool,
    
    /// Enable ICMP rate limiting
    #[arg(long)]
    enable_icmp_ratelimit: bool,
    
    /// Enable allowlist mode
    #[arg(long)]
    enable_allowlist: bool,
    
    /// Allowlist ports (comma-separated, e.g., "22,8080")
    #[arg(long)]
    allowlist_ports: Option<String>,
    
    /// Allowlist IPs (comma-separated, e.g., "1.2.3.4,5.6.7.8")
    #[arg(long)]
    allowlist_ips: Option<String>,
    
    /// Enable GeoIP blocking
    #[arg(long)]
    enable_geoip: bool,
    
    /// Blocked country codes (comma-separated, e.g., "CN,RU,KP")
    #[arg(long)]
    blocked_countries: Option<String>,
    
    /// Path to GeoIP database (MaxMind GeoLite2 format)
    #[arg(long)]
    geoip_db: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Setup logging
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .compact()
        .init();
    
    println!("{}", BANNER);
    
    info!("🛡️ Starting HEIMDALL-RS on interface: {}", args.interface);
    
    // Parse gateway ports
    let gateway_ports: Vec<u16> = if let Some(ports_str) = args.gateway_ports {
        ports_str.split(',').filter_map(|p| p.trim().parse().ok()).collect()
    } else {
        Vec::new()
    };
    
    // Parse allowlist ports
    let allowlist_ports: Vec<u16> = if let Some(ports_str) = args.allowlist_ports {
        ports_str.split(',').filter_map(|p| p.trim().parse().ok()).collect()
    } else {
        Vec::new()
    };
    
    // Parse allowlist IPs
    let allowlist_ips: Vec<std::net::IpAddr> = if let Some(ips_str) = args.allowlist_ips {
        ips_str.split(',').filter_map(|ip| ip.trim().parse().ok()).collect()
    } else {
        Vec::new()
    };
    
    // Build configuration
    let config = config::Config {
        interface: args.interface,
        mode: args.mode,
        ebpf_path: args.ebpf,
        svalinn_url: args.svalinn,
        api_key: args.apikey,
        sync_interval_secs: args.sync_interval,
        min_score: args.min_score,
        autoblock: args.autoblock,
        monitor_only: args.monitor_only,
        ban_ttl_secs: args.ban_ttl,
        prom_addr: args.prom_addr,
        failsafe_enabled: args.failsafe,
        failsafe_threshold: args.failsafe_threshold,
        chain_ebpf: args.chain_ebpf,
        gateway_mode: args.gateway_mode,
        gateway_ports,
        enable_udp_ratelimit: args.enable_udp_ratelimit,
        enable_icmp_ratelimit: args.enable_icmp_ratelimit,
        enable_allowlist: args.enable_allowlist,
        allowlist_ports,
        allowlist_ips,
        enable_geoip: args.enable_geoip,
        blocked_countries: args.blocked_countries
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_uppercase())
            .collect(),
        geoip_db_path: args.geoip_db,
    };
    
    // Create and run agent
    let mut agent = agent::Agent::new(config).await?;
    agent.run().await?;
    
    Ok(())
}
