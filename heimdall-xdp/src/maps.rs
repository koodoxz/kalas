//! Blocklist Map Management

use aya::maps::HashMap;
use aya::Pod;
use anyhow::Result;
use std::net::IpAddr;
use tracing::{debug, info};

/// Block an IPv4 address in the provided map
pub fn block_ipv4(
    map: &mut HashMap<&mut aya::maps::MapData, u32, u64>,
    ip: std::net::Ipv4Addr,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = u32::from_be_bytes(ip.octets());
    map.insert(&key, &now, 0)?;
    debug!("Blocked IPv4: {}", ip);
    Ok(())
}

/// Block an IPv6 address in the provided map
pub fn block_ipv6(
    map: &mut HashMap<&mut aya::maps::MapData, [u8; 16], u64>,
    ip: std::net::Ipv6Addr,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = ip.octets();
    map.insert(&key, &now, 0)?;
    debug!("Blocked IPv6: {}", ip);
    Ok(())
}

/// Unblock an IPv4 address
pub fn unblock_ipv4(
    map: &mut HashMap<&mut aya::maps::MapData, u32, u64>,
    ip: std::net::Ipv4Addr,
) -> Result<()> {
    let key = u32::from_be_bytes(ip.octets());
    map.remove(&key)?;
    debug!("Unblocked IPv4: {}", ip);
    Ok(())
}

/// Check if IPv4 is blocked
pub fn is_ipv4_blocked(
    map: &HashMap<&aya::maps::MapData, u32, u64>,
    ip: std::net::Ipv4Addr,
) -> bool {
    let key = u32::from_be_bytes(ip.octets());
    map.get(&key, 0).is_ok()
}
