//! Statistics Collection

use aya::maps::PerCpuArray;
use aya::Ebpf;
use crate::types::Stats;
use anyhow::{Context, Result};

pub struct StatsReader<'a> {
    stats_map: PerCpuArray<&'a aya::maps::MapData, Stats>,
}

impl<'a> StatsReader<'a> {
    pub fn new(ebpf: &'a Ebpf) -> Result<Self> {
        let stats_map = PerCpuArray::try_from(
            ebpf.map("STATS").context("STATS map not found")?
        )?;
        
        Ok(Self { stats_map })
    }
    
    /// Get aggregated stats from all CPUs
    pub fn get_stats(&self) -> Result<Stats> {
        let per_cpu_stats = self.stats_map.get(&0, 0)?;
        
        let mut aggregated = Stats::default();
        for cpu_stats in per_cpu_stats.iter() {
            aggregated.total_packets = aggregated.total_packets.saturating_add(cpu_stats.total_packets);
            aggregated.blocked_packets = aggregated.blocked_packets.saturating_add(cpu_stats.blocked_packets);
            aggregated.passed_packets = aggregated.passed_packets.saturating_add(cpu_stats.passed_packets);
            aggregated.ipv4_packets = aggregated.ipv4_packets.saturating_add(cpu_stats.ipv4_packets);
            aggregated.ipv6_packets = aggregated.ipv6_packets.saturating_add(cpu_stats.ipv6_packets);
            aggregated.syn_rate_limited = aggregated.syn_rate_limited.saturating_add(cpu_stats.syn_rate_limited);
            aggregated.port_scan_detected = aggregated.port_scan_detected.saturating_add(cpu_stats.port_scan_detected);
        }
        
        Ok(aggregated)
    }
}
