# HEIMDALL-RS Feature Roadmap

> L3/L4 Intelligent Firewall — Future Development

---

## Current Features (v0.1.0) ✅

### Production (All VPS)
| Feature | Description | Status |
|---------|-------------|--------|
| **IP Blocklist** | IPv4/IPv6 blocklist via LruHashMap | ✅ Production |
| **SYN Rate Limiting** | Token bucket algorithm (100 req/s, burst 200) | ✅ Production |
| **Port Scan Detection** | 20 connections in 10s window triggers alert | ✅ Production |
| **XDP Chain** | Tail-call to MIMIR XDP via JUMP_TABLE | ✅ Production |
| **SVALINN Integration** | Sync threat intelligence from hub | ✅ Production |
| **Prometheus Metrics** | Full observability (blocked, syn_flood, port_scan) | ✅ Production |
| **Auto-block Mode** | Automatically block detected threats | ✅ Production |

### P1 Features (HEIMDALL Test VPS Only)
| Feature | Description | Status |
|---------|-------------|--------|
| **Smart Passthrough Mode** | Gateway ports bypass rate limiting (53,853,8853,443) | ✅ Test VPS |
| **UDP Rate Limiting** | Per-IP UDP packet rate limiting | ✅ Test VPS |
| **ICMP Rate Limiting** | Per-IP ICMP packet rate limiting | ✅ Test VPS |
| **Gateway Mode CLI** | CLI flags for gateway configuration | ✅ Test VPS |

> **Deployment Strategy:** P1-P4 features developed on a dedicated HEIMDALL Test VPS, then deployed to production after validation.

---

## Priority Matrix — Future Features

### P1: High Priority ✅ COMPLETED (Feb 5, 2026)

#### 1. Smart Passthrough Mode ✅
**Purpose**: Minimize latency overhead for gateway servers (e.g., ODIN)

**Implementation**: 
- Gateway mode CLI flag (`--gateway-mode`)
- Configurable gateway ports (`--gateway-ports 53,853,8853,443`)
- eBPF CONFIG map for runtime control
- Fast-path for gateway traffic

**Status**: ✅ Deployed on HEIMDALL Test VPS

#### 2. Per-IP Rate Limiting (Enhanced) ✅
**Purpose**: More granular rate limiting beyond just SYN packets

**Implementation**:
- UDP rate limiting (`--enable-udp-ratelimit`)
- ICMP rate limiting (`--enable-icmp-ratelimit`)
- Per-IP tracking with token bucket algorithm
- eBPF map-based configuration

**Status**: ✅ Deployed on HEIMDALL Test VPS

---

### P2: Medium Priority

#### 3. GeoIP Blocking
**Purpose**: Block traffic from high-risk countries at kernel level

```rust
#[map]
static BLOCKED_COUNTRIES: LruHashMap<u8, u8> = LruHashMap::with_max_entries(256, 0);

#[map]
static GEOIP_DB: LruHashMap<u32, u8> = LruHashMap::with_max_entries(1_000_000, 0);

// In XDP program
let country = GEOIP_DB.get(&src_ip);
if BLOCKED_COUNTRIES.get(&country).is_some() {
    return XDP_DROP;
}
```

**Requirements**: 
- GeoIP database (MaxMind GeoLite2)
- Userspace loader to populate GEOIP_DB map
- SVALINN API for country blocklist

**Impact**: Block entire regions (e.g., known attack sources)
**Complexity**: Medium
**ETA**: 3-5 days

#### 4. Allowlist Mode
**Purpose**: Restrict access to whitelisted IPs only (for admin panels, critical services)

```rust
#[map]
static ALLOWLIST_V4: LruHashMap<u32, u8> = LruHashMap::with_max_entries(10_000, 0);

// Check if allowlist mode is enabled for this port
if ALLOWLIST_PORTS.get(&dst_port).is_some() {
    if ALLOWLIST_V4.get(&src_ip).is_none() {
        return XDP_DROP;
    }
}
```

**Impact**: Strong protection for sensitive endpoints
**Complexity**: Low
**ETA**: 1-2 days

---

### P3: Lower Priority

#### 5. Connection Tracking (Stateful Firewall)
**Purpose**: Track TCP states, drop invalid packets

```rust
#[repr(C)]
struct ConnTrackEntry {
    state: u8,        // SYN_SENT, ESTABLISHED, FIN_WAIT, etc.
    last_seen: u64,
    seq_num: u32,
    ack_num: u32,
}

#[map]
static CONNTRACK: LruHashMap<ConnTrackKey, ConnTrackEntry> = LruHashMap::with_max_entries(500_000, 0);
```

**Impact**: Drop spoofed/invalid TCP packets
**Complexity**: High (TCP state machine in eBPF)
**ETA**: 1-2 weeks

#### 6. Traffic Mirroring (Forensics)
**Purpose**: Mirror suspicious traffic to analysis server

```rust
// XDP_REDIRECT to mirror interface
if is_suspicious {
    bpf_clone_redirect(ctx, mirror_ifindex, 0);
}
```

**Impact**: Security analysis, honeypot integration
**Complexity**: Medium
**ETA**: 3-5 days

---

## Architecture Evolution

### Current (v0.1.0)
```
HEIMDALL XDP
    ↓
BLOCKLIST check → DROP
    ↓
SYN rate limit → DROP
    ↓
Port scan detect → ALERT
    ↓
JUMP_TABLE[0] → MIMIR XDP (if configured)
    ↓
XDP_PASS
```

### Future (v0.2.0)
```
HEIMDALL XDP
    ↓
CONFIG check (smart passthrough mode?)
    ↓
ALLOWLIST check (if enabled) → DROP if not in list
    ↓
BLOCKLIST check → DROP
    ↓
GEOIP check → DROP if blocked country
    ↓
Rate limit (SYN/UDP/ICMP/Total) → DROP
    ↓
Port scan detect → ALERT + optional auto-block
    ↓
CONNTRACK check → DROP invalid packets
    ↓
JUMP_TABLE[0] → MIMIR XDP (if configured)
    ↓
XDP_PASS (with optional mirror)
```

---

## Implementation Notes

### Smart Passthrough for Gateway Servers
When HEIMDALL runs on gateway servers like ODIN:
1. Most traffic is legitimate (DoH/DoT/DoQ clients)
2. Full processing adds latency to every packet
3. Solution: Configurable "gateway mode" that:
   - Only checks blocklist (O(1) lookup)
   - Skips rate limiting for gateway ports
   - Minimal overhead for clean traffic

### On/Off Control
All features should be toggleable via:
1. eBPF map flags (real-time toggle)
2. SVALINN dashboard (future)
3. CLI flags (startup configuration)

---

## Timeline

| Quarter | Milestone |
|---------|-----------|
| Q1 2026 | P1 features (Smart Passthrough, Enhanced Rate Limiting) |
| Q2 2026 | P2 features (GeoIP, Allowlist) |
| Q3 2026 | P3 features (Conntrack, Mirroring) |
| Q4 2026 | SVALINN Dashboard integration |

---

**Last Updated**: 2026-01-13
**Author**: AEGIS Development Team
