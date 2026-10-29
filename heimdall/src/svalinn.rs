//! SVALINN Client for Threat Intelligence Sync

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct SvalinnClient {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    node_id: String,
    min_score: u64,
}

#[derive(Debug, Deserialize)]
pub struct ThreatFeed {
    #[serde(default)]
    pub threats: Vec<Threat>,
    #[serde(default)]
    pub ip_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct Threat {
    pub ip: String,
    #[serde(default)]
    pub score: u64,
    #[serde(default)]
    pub threat_type: String,
}

#[derive(Debug, Serialize)]
struct ThreatReport {
    ip: String,
    threat_type: String,
    severity: u8,
    evidence: String,
    node_id: String,
}

impl SvalinnClient {
    pub fn new(base_url: &str, api_key: &str, node_id: &str, min_score: u64) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            node_id: node_id.to_string(),
            min_score,
        }
    }
    
    /// Fetch threat blocklist from SVALINN Hub
    pub async fn fetch_threats(&self) -> Result<ThreatFeed> {
        let url = format!("{}/api/v1/shield/threats", self.base_url);
        
        let resp = self.client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .send()
            .await
            .context("Failed to connect to SVALINN")?;
        
        if !resp.status().is_success() {
            anyhow::bail!("SVALINN returned status: {}", resp.status());
        }
        
        let feed: ThreatFeed = resp.json().await.context("Failed to parse threat feed")?;
        debug!("Fetched {} threats from SVALINN", feed.threats.len());
        Ok(feed)
    }
    
    /// Extract IPs that meet the minimum score threshold
    pub fn extract_ips(&self, feed: &ThreatFeed) -> Vec<IpAddr> {
        feed.threats
            .iter()
            .filter(|t| t.score >= self.min_score)
            .filter_map(|t| t.ip.parse().ok())
            .collect()
    }
    
    /// Report a detected threat to SVALINN Hub
    pub async fn report_threat(
        &self,
        ip: &str,
        threat_type: &str,
        severity: u8,
        evidence: &str,
    ) -> Result<()> {
        let url = format!("{}/api/v1/heimdall/report", self.base_url);
        
        let report = ThreatReport {
            ip: ip.to_string(),
            threat_type: threat_type.to_string(),
            severity,
            evidence: evidence.to_string(),
            node_id: self.node_id.clone(),
        };
        
        let resp = self.client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .json(&report)
            .send()
            .await
            .context("Failed to report threat to SVALINN")?;
        
        if !resp.status().is_success() {
            warn!("SVALINN report failed: {}", resp.status());
        } else {
            debug!("Reported {} threat for {} to SVALINN", threat_type, ip);
        }
        
        Ok(())
    }
}
