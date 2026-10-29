//! Prometheus Metrics Server

use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{Encoder, TextEncoder, Counter, Gauge, Registry};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub struct Metrics {
    pub registry: Registry,
    pub blocked_total: Counter,
    pub syn_flood_total: Counter,
    pub port_scan_total: Counter,
    pub active_blocks: Gauge,
    pub packets_total: Counter,
    // P1: New metrics
    pub udp_flood_total: Counter,
    pub icmp_flood_total: Counter,
    pub gateway_fast_path_total: Counter,
    // P2: New metrics
    pub geoip_blocked_total: Counter,
    pub allowlist_denied_total: Counter,
    pub threat_report_dropped_total: Counter,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        
        let blocked_total = Counter::new("heimdall_blocked_total", "Total blocked packets").unwrap();
        let syn_flood_total = Counter::new("heimdall_syn_flood_total", "SYN flood detections").unwrap();
        let port_scan_total = Counter::new("heimdall_port_scan_total", "Port scan detections").unwrap();
        let active_blocks = Gauge::new("heimdall_active_blocks", "Currently blocked IPs").unwrap();
        let packets_total = Counter::new("heimdall_packets_total", "Total packets processed").unwrap();
        // P1: New metrics
        let udp_flood_total = Counter::new("heimdall_udp_flood_total", "UDP flood rate limited").unwrap();
        let icmp_flood_total = Counter::new("heimdall_icmp_flood_total", "ICMP flood rate limited").unwrap();
        let gateway_fast_path_total = Counter::new("heimdall_gateway_fast_path_total", "Gateway mode fast path packets").unwrap();
        // P2: New metrics
        let geoip_blocked_total = Counter::new("heimdall_geoip_blocked_total", "GeoIP blocked packets").unwrap();
        let allowlist_denied_total = Counter::new("heimdall_allowlist_denied_total", "Allowlist denied packets").unwrap();
        let threat_report_dropped_total = Counter::new("heimdall_threat_report_dropped_total", "SVALINN threat reports dropped due to full queue").unwrap();

        registry.register(Box::new(blocked_total.clone())).unwrap();
        registry.register(Box::new(syn_flood_total.clone())).unwrap();
        registry.register(Box::new(port_scan_total.clone())).unwrap();
        registry.register(Box::new(active_blocks.clone())).unwrap();
        registry.register(Box::new(packets_total.clone())).unwrap();
        registry.register(Box::new(udp_flood_total.clone())).unwrap();
        registry.register(Box::new(icmp_flood_total.clone())).unwrap();
        registry.register(Box::new(gateway_fast_path_total.clone())).unwrap();
        registry.register(Box::new(geoip_blocked_total.clone())).unwrap();
        registry.register(Box::new(allowlist_denied_total.clone())).unwrap();
        registry.register(Box::new(threat_report_dropped_total.clone())).unwrap();

        Self {
            registry,
            blocked_total,
            syn_flood_total,
            port_scan_total,
            active_blocks,
            packets_total,
            udp_flood_total,
            icmp_flood_total,
            gateway_fast_path_total,
            geoip_blocked_total,
            allowlist_denied_total,
            threat_report_dropped_total,
        }
    }
}

pub async fn start_metrics_server(addr: &str, metrics: Arc<RwLock<Metrics>>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("📊 Prometheus metrics at http://{}/metrics", addr);
    
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let metrics = Arc::clone(&metrics);
        
        tokio::spawn(async move {
            let service = service_fn(|req| {
                let metrics = Arc::clone(&metrics);
                async move {
                    handle_request(req, metrics).await
                }
            });
            
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                warn!("Metrics server error: {}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    metrics: Arc<RwLock<Metrics>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    
    match path {
        "/metrics" => {
            let metrics = metrics.read().await;
            let encoder = TextEncoder::new();
            let metric_families = metrics.registry.gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from(buffer)))
                .unwrap())
        }
        "/health" => {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from("OK")))
                .unwrap())
        }
        _ => {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap())
        }
    }
}
