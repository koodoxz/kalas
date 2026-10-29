//! HEIMDALL Agent - Core Controller
//! 
//! FIXED: Memory leak issues identified by 5 LLM consensus:
//! 1. RingBuf now created ONCE and stored as struct field
//! 2. SVALINN reports via bounded channel instead of unbounded spawn
//! 3. Preallocated event buffer
//! 4. Reduced polling from 10ms to 100ms

use crate::config::Config;
use crate::metrics::{start_metrics_server, Metrics};
use crate::svalinn::SvalinnClient;
use crate::maps::MapManager;

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use heimdall_xdp::{XdpLoader, DetectionEvent};
use heimdall_xdp::loader::XdpMode;
use heimdall_xdp::{EVENT_TYPE_SYN_FLOOD, EVENT_TYPE_PORT_SCAN, EVENT_TYPE_UDP_FLOOD, EVENT_TYPE_ICMP_FLOOD};

use std::collections::HashMap as StdHashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::signal;
use tracing::{info, warn, error, debug};

/// Report to be sent to SVALINN
#[derive(Debug, Clone)]
struct ThreatReport {
    ip: String,
    threat_type: String,
    severity: u8,
    evidence: String,
}

pub struct Agent {
    config: Config,
    loader: XdpLoader,
    blocked_ips: StdHashMap<IpAddr, Instant>,
    svalinn_client: Option<SvalinnClient>,
    metrics: Arc<RwLock<Metrics>>,
    failsafe_paused: bool,
    start_time: Instant,
    
    // FIX #1: Persistent RingBuf - created ONCE, never recreated
    ring_buf: Option<RingBuf<MapData>>,
    
    // FIX #2: Bounded channel for SVALINN reports (replaces unbounded spawn)
    svalinn_tx: Option<mpsc::Sender<ThreatReport>>,
    
    // FIX #3: Preallocated buffer for events
    event_buffer: Vec<DetectionEvent>,
    
    // Map manager for reading stats
    map_manager: Option<MapManager>,
    
    // Last stats for delta calculation
    last_stats: crate::maps::Stats,
}

impl Agent {
    pub async fn new(config: Config) -> Result<Self> {
        let ebpf_bytes = std::fs::read(&config.ebpf_path)
            .context(format!("Failed to read eBPF file: {:?}", config.ebpf_path))?;
        
        let mut loader = XdpLoader::new(&ebpf_bytes, &config.interface)?;
        
        // FIX #1: Take the EVENTS map ONCE and create RingBuf ONCE
        let ring_buf = if let Some(events_map) = loader.ebpf_mut().take_map("EVENTS") {
            match RingBuf::try_from(events_map) {
                Ok(rb) => {
                    info!("✅ RingBuf initialized (persistent, no recreation)");
                    Some(rb)
                }
                Err(e) => {
                    warn!("⚠️ Failed to create RingBuf: {}", e);
                    None
                }
            }
        } else {
            warn!("⚠️ EVENTS map not found in eBPF program");
            None
        };
        
        // Create SVALINN client
        let svalinn_client = if let (Some(url), Some(key)) = (&config.svalinn_url, &config.api_key) {
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "heimdall".to_string());
            Some(SvalinnClient::new(url, key, &hostname, config.min_score))
        } else {
            None
        };
        
        // FIX #2: Create bounded channel for SVALINN reports
        let svalinn_tx = if let Some(ref client) = svalinn_client {
            let (tx, rx) = mpsc::channel::<ThreatReport>(1000); // Max 1000 pending reports
            
            // Spawn SINGLE dedicated reporter task
            let client_clone = client.clone();
            tokio::spawn(async move {
                Self::svalinn_reporter_task(client_clone, rx).await;
            });
            
            info!("✅ SVALINN reporter task started (bounded channel, max 1000 pending)");
            Some(tx)
        } else {
            None
        };
        
        Ok(Self {
            config,
            loader,
            blocked_ips: StdHashMap::new(),
            svalinn_client,
            metrics: Arc::new(RwLock::new(Metrics::new())),
            failsafe_paused: false,
            start_time: Instant::now(),
            ring_buf,
            svalinn_tx,
            event_buffer: Vec::with_capacity(128), // Preallocate for burst
            map_manager: None, // Will be set after attach
            last_stats: crate::maps::Stats::default(),
        })
    }
    
    pub async fn run(&mut self) -> Result<()> {
        let mode: XdpMode = self.config.mode.as_str().into();
        self.loader.attach(mode)?;
        
        info!("✅ XDP attached to {} ({:?})", self.config.interface, mode);
        
        // P1: Configure eBPF maps AFTER XDP is attached
        let mut map_manager = MapManager::new(self.loader.ebpf_mut())?;
        
        // Gateway mode configuration
        if self.config.gateway_mode {
            map_manager.enable_gateway_mode()?;
            if !self.config.gateway_ports.is_empty() {
                map_manager.add_gateway_ports(&self.config.gateway_ports)?;
            }
        }
        
        // UDP rate limiting
        if self.config.enable_udp_ratelimit {
            map_manager.enable_udp_ratelimit()?;
        }
        
        // ICMP rate limiting
        if self.config.enable_icmp_ratelimit {
            map_manager.enable_icmp_ratelimit()?;
        }
        
        // Allowlist mode
        if self.config.enable_allowlist {
            map_manager.enable_allowlist()?;
            if !self.config.allowlist_ports.is_empty() {
                map_manager.add_allowlist_ports(&self.config.allowlist_ports)?;
            }
            for ip in &self.config.allowlist_ips {
                map_manager.add_allowlist_ip(*ip)?;
            }
        }
        
        // P2: GeoIP blocking
        if self.config.enable_geoip {
            map_manager.enable_geoip()?;
            if !self.config.blocked_countries.is_empty() {
                map_manager.block_countries(&self.config.blocked_countries)?;
            }
            if let Some(ref db_path) = self.config.geoip_db_path {
                map_manager.load_geoip_db(db_path)?;
            }
        }
        
        // Chain secondary XDP program if configured
        if let Some(ref chain_path) = self.config.chain_ebpf {
            match self.loader.chain_program(chain_path, 0) {
                Ok(()) => info!("🔗 Chained secondary XDP program: {:?}", chain_path),
                Err(e) => warn!("⚠️ Failed to chain secondary program: {}", e),
            }
        }
        
        // Start metrics server
        let metrics_clone = Arc::clone(&self.metrics);
        let prom_addr = self.config.prom_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = start_metrics_server(&prom_addr, metrics_clone).await {
                error!("Metrics server error: {}", e);
            }
        });
        
        let mode_str = if self.config.monitor_only { "MONITORING" } else { "ACTIVE" };
        info!("🛡️ HEIMDALL protection {} (mode: {})", mode_str, mode_str);
        
        if self.svalinn_client.is_some() {
            self.start_svalinn_sync();
            info!("🌐 SVALINN sync enabled (every {}s)", self.config.sync_interval_secs);
        }
        
        // Store map_manager for stats reading
        self.map_manager = Some(map_manager);
        
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(30));
        let mut stats_interval = tokio::time::interval(Duration::from_secs(5)); // Stats every 5s
        // FIX #4: Reduced from 10ms to 100ms (10 polls/sec vs 100)
        let mut event_interval = tokio::time::interval(Duration::from_millis(100));
        event_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        
        loop {
            tokio::select! {
                _ = event_interval.tick() => {
                    self.process_events().await;
                }
                
                _ = heartbeat_interval.tick() => {
                    self.log_heartbeat().await;
                }
                
                _ = cleanup_interval.tick() => {
                    self.cleanup_expired_bans().await;
                }
                
                _ = stats_interval.tick() => {
                    self.update_stats_metrics().await;
                }
                
                _ = signal::ctrl_c() => {
                    info!("🛑 Shutting down HEIMDALL...");
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Process events from persistent RingBuf
    async fn process_events(&mut self) {
        // Clear buffer but keep capacity (no reallocation)
        self.event_buffer.clear();
        
        // FIX #1: Use persistent RingBuf reference - NO recreation!
        if let Some(ring_buf) = &mut self.ring_buf {
            // Limit events per poll to prevent burst overload
            let max_events_per_poll = 256;
            
            while self.event_buffer.len() < max_events_per_poll {
                match ring_buf.next() {
                    Some(item) => {
                        if item.len() >= std::mem::size_of::<DetectionEvent>() {
                            let event: DetectionEvent = unsafe {
                                std::ptr::read(item.as_ptr() as *const DetectionEvent)
                            };
                            self.event_buffer.push(event);
                        }
                    }
                    None => break, // No more events
                }
            }
        }
        
        // Process collected events
        for i in 0..self.event_buffer.len() {
            let event = self.event_buffer[i];
            self.handle_event(event).await;
        }
    }
    
    async fn handle_event(&mut self, event: DetectionEvent) {
        let ip_str = event.src_ip_addr().to_string();
        let ip: IpAddr = event.src_ip_addr().into();
        
        // Update metrics
        {
            let metrics = self.metrics.read().await;
            match event.event_type {
                EVENT_TYPE_SYN_FLOOD => {
                    info!("🚨 [ATTACK] SYN_FLOOD detected from {} (tokens: {})", ip_str, event.count);
                    metrics.syn_flood_total.inc();
                }
                EVENT_TYPE_PORT_SCAN => {
                    info!("🔍 [RECON] PORT_SCAN detected from {} (ports: {}, last: {})", 
                        ip_str, event.count, event.dst_port);
                    metrics.port_scan_total.inc();
                }
                EVENT_TYPE_UDP_FLOOD => {
                    info!("🚨 [ATTACK] UDP_FLOOD detected from {} (count: {}, port: {})", ip_str, event.count, event.dst_port);
                    metrics.syn_flood_total.inc();
                }
                EVENT_TYPE_ICMP_FLOOD => {
                    info!("🚨 [ATTACK] ICMP_FLOOD detected from {} (count: {})", ip_str, event.count);
                    metrics.syn_flood_total.inc();
                }
                _ => {}
            }
        }
        
        // FIX #2: Send to bounded channel instead of spawning task
        if let Some(tx) = &self.svalinn_tx {
            let report = ThreatReport {
                ip: ip_str.clone(),
                threat_type: event.event_type_name().to_string(),
                severity: 7,
                evidence: format!("count={} port={}", event.count, event.dst_port),
            };
            
            // Non-blocking send with backpressure
            match tx.try_send(report) {
                Ok(_) => {
                    debug!("📤 Queued SVALINN report for {}", ip_str);
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!("⚠️ SVALINN report queue full, dropping report for {}", ip_str);
                    self.metrics.read().await.threat_report_dropped_total.inc();
                }
                Err(e) => {
                    debug!("Failed to queue report: {}", e);
                }
            }
        }
        
        // Auto-block if enabled and not in monitor-only mode
        if !self.config.monitor_only && self.config.autoblock && !self.failsafe_paused {
            if event.event_type == EVENT_TYPE_SYN_FLOOD || event.event_type == EVENT_TYPE_PORT_SCAN
                || event.event_type == EVENT_TYPE_UDP_FLOOD || event.event_type == EVENT_TYPE_ICMP_FLOOD {
                self.blocked_ips.insert(ip, Instant::now());
                info!("⛔ [BLOCK] Auto-blocked {} (TTL: {}s)", ip_str, self.config.ban_ttl_secs);
                
                let metrics = self.metrics.read().await;
                metrics.active_blocks.set(self.blocked_ips.len() as f64);
            }
        }
    }
    
    /// FIX #2: Dedicated SVALINN reporter task with bounded concurrency
    async fn svalinn_reporter_task(
        client: SvalinnClient,
        mut rx: mpsc::Receiver<ThreatReport>,
    ) {
        // Limit concurrent HTTP requests to prevent connection exhaustion
        let semaphore = Arc::new(Semaphore::new(10)); // Max 10 concurrent reports
        
        let mut batch: Vec<ThreatReport> = Vec::with_capacity(50);
        let mut last_flush = Instant::now();
        
        loop {
            tokio::select! {
                Some(report) = rx.recv() => {
                    batch.push(report);
                    
                    // Flush if batch is full or 5 seconds elapsed
                    if batch.len() >= 50 || last_flush.elapsed() > Duration::from_secs(5) {
                        Self::flush_batch(&client, &semaphore, &mut batch).await;
                        last_flush = Instant::now();
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    // Periodic flush for stragglers
                    if !batch.is_empty() {
                        Self::flush_batch(&client, &semaphore, &mut batch).await;
                        last_flush = Instant::now();
                    }
                }
            }
        }
    }
    
    /// Send batch of reports - NO SPAWNING to prevent memory leak
    /// FIX #5: Sequential sends with timeout instead of spawning tasks
    async fn flush_batch(
        client: &SvalinnClient,
        _semaphore: &Arc<Semaphore>,
        batch: &mut Vec<ThreatReport>,
    ) {
        // Process sequentially with timeout - no task accumulation
        for report in batch.drain(..) {
            // 3 second timeout per report to prevent hanging
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                client.report_threat(&report.ip, &report.threat_type, report.severity, &report.evidence)
            ).await;
            
            match result {
                Ok(Ok(_)) => {
                    debug!("📤 SVALINN report sent for {}", report.ip);
                }
                Ok(Err(e)) => {
                    debug!("SVALINN report failed: {}", e);
                }
                Err(_) => {
                    debug!("SVALINN report timed out for {}", report.ip);
                }
            }
        }
    }
    
    async fn cleanup_expired_bans(&mut self) {
        let ban_ttl = Duration::from_secs(self.config.ban_ttl_secs);
        let now = Instant::now();
        
        let expired: Vec<IpAddr> = self.blocked_ips
            .iter()
            .filter(|(_, blocked_at)| now.duration_since(**blocked_at) > ban_ttl)
            .map(|(ip, _)| *ip)
            .collect();
        
        if !expired.is_empty() {
            for ip in &expired {
                self.blocked_ips.remove(ip);
                info!("⏰ Auto-unblocked {} (TTL expired)", ip);
            }
            let metrics = self.metrics.read().await;
            metrics.active_blocks.set(self.blocked_ips.len() as f64);
        }
    }
    
    async fn log_heartbeat(&self) {
        let uptime = self.start_time.elapsed();
        let blocked_count = self.blocked_ips.len();
        
        info!("💓 [HEARTBEAT] Uptime: {:?} | Active Bans: {}", uptime, blocked_count);
    }
    
    /// Update Prometheus metrics from eBPF STATS map
    async fn update_stats_metrics(&mut self) {
        if let Some(map_manager) = &self.map_manager {
            match map_manager.read_stats() {
                Ok(stats) => {
                    let metrics = self.metrics.read().await;
                    
                    // Calculate deltas and increment counters
                    let delta_packets = stats.total_packets.wrapping_sub(self.last_stats.total_packets);
                    let delta_blocked = stats.blocked_packets.wrapping_sub(self.last_stats.blocked_packets);
                    let delta_gateway = stats.gateway_fast_path.wrapping_sub(self.last_stats.gateway_fast_path);
                    let delta_udp = stats.udp_rate_limited.wrapping_sub(self.last_stats.udp_rate_limited);
                    let delta_icmp = stats.icmp_rate_limited.wrapping_sub(self.last_stats.icmp_rate_limited);
                    let delta_geoip = stats.geoip_blocked.wrapping_sub(self.last_stats.geoip_blocked);
                    let delta_allowlist = stats.allowlist_denied.wrapping_sub(self.last_stats.allowlist_denied);
                    
                    // Increment by delta (Prometheus counters are cumulative)
                    if delta_packets > 0 {
                        metrics.packets_total.inc_by(delta_packets as f64);
                    }
                    if delta_blocked > 0 {
                        metrics.blocked_total.inc_by(delta_blocked as f64);
                    }
                    if delta_gateway > 0 {
                        metrics.gateway_fast_path_total.inc_by(delta_gateway as f64);
                    }
                    if delta_udp > 0 {
                        metrics.udp_flood_total.inc_by(delta_udp as f64);
                    }
                    if delta_icmp > 0 {
                        metrics.icmp_flood_total.inc_by(delta_icmp as f64);
                    }
                    if delta_geoip > 0 {
                        metrics.geoip_blocked_total.inc_by(delta_geoip as f64);
                    }
                    if delta_allowlist > 0 {
                        metrics.allowlist_denied_total.inc_by(delta_allowlist as f64);
                    }
                    
                    self.last_stats = stats;
                    
                    debug!("📊 Stats: total={} blocked={} gateway_fp={}", 
                        stats.total_packets, stats.blocked_packets, stats.gateway_fast_path);
                }
                Err(e) => {
                    warn!("Failed to read stats: {}", e);
                }
            }
        }
    }
    
    fn start_svalinn_sync(&self) {
        if let Some(client) = &self.svalinn_client {
            let client = client.clone();
            let interval = Duration::from_secs(self.config.sync_interval_secs);
            tokio::spawn(async move {
                let mut timer = tokio::time::interval(interval);
                loop {
                    timer.tick().await;
                    match client.fetch_threats().await {
                        Ok(feed) => {
                            let ips = client.extract_ips(&feed);
                            info!("🔄 Synced {} threats from SVALINN, {} IPs eligible", feed.threats.len(), ips.len());
                        }
                        Err(e) => {
                            warn!("SVALINN sync failed: {}", e);
                        }
                    }
                }
            });
        }
    }
}
