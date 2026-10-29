# Kalas (KALAS) ᚲᚨᛚᚨᛋ

> **High-Speed Layer 3 & Layer 4 Kernel Firewall — Engineered in Rust via eBPF/XDP**  
> Wire-speed packet dropping (XDP_DROP), SYN flood suppression, zero-copy AF_XDP ring buffers, and dynamic threat map synchronization.

[![CI](https://github.com/koodoxz/kalas/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/koodoxz/kalas/actions)
[![Rust](https://img.shields.io/badge/Rust-1.75+-000000?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/Linux-eBPF%20%7C%20AF__XDP-orange.svg)](#architecture)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-Architecture%20Portal-00f2fe.svg)](https://koodoxz.github.io)

---

## Executive Summary

**Kalas** (Austronesian / Javanese: *"resilient perimeter binding / protective border node"*) is a high-speed Layer 3 & Layer 4 kernel firewall written in Rust using eBPF and AF_XDP. It operates as the foundational kernel defense substrate within the host operating system, shielding userspace services (such as [Gapura](https://github.com/koodoxz/gapura) and [Runut](https://github.com/koodoxz/runut)) from volumetric network attacks.

Traditional Linux packet filtering frameworks (`iptables`, `nftables`, `ufw`) process traffic after the kernel allocates socket buffers (`sk_buff`) and invokes CPU interrupt handlers (`softirq`). Under multi-gigabit volumetric floods (SYN floods, UDP amplification, ACK floods), CPU resources saturate entirely on memory allocation alone, degrading legitimate application throughput.

**Kalas eliminates this bottleneck by executing directly inside the Network Interface Card (NIC) driver layer via eXpress Data Path (XDP)**. Malicious frames are evaluated against lock-free eBPF maps and discarded via `XDP_DROP` in sub-microsecond time, completely preventing packet allocation in kernel RAM.

---

## The Defense Ecosystem

Kalas operates as the kernel-level perimeter substrate within the unified MECOB defense infrastructure:

```
[ Client / Edge Devices ]
           │
           ▼ (Plaintext DNS on localhost)
   ┌──────────────┐
   │    Caraka    │  Lightweight DNS over QUIC (DoQ) Edge Forwarder
   └──────┬───────┘
          │ (Encrypted DoQ / QUIC - Port 8853)
          ▼
   ┌──────────────┐   eBPF / XDP Kernel Firewall
   │    Gapura    │◄───[ Kalas ] (Layer 3 & Layer 4 Anti-DDoS Filter)
   └──────┬───────┘   Public Ingress Gateway (Rate-Limiting & TLS Termination)
          │
          │ (Air-Gapped Unix Domain Socket / IPC)
          ▼
   ┌──────────────┐   Real-Time Threat Feeds
   │    Runut     │◄─────────────────────────► [ Tameng ]
   └──────┬───────┘   Authoritative Root DNS   Autonomous L7 WAF
          │
          ▼ (Direct iterative queries)
[ 13 Internet Root Servers (A.ROOT .. M.ROOT) ]
```

| Component | Layer / Scope | Role in Ecosystem |
| :--- | :--- | :--- |
| **[Kalas](https://github.com/koodoxz/kalas)** | Layer 3 & 4 (Kernel) | eBPF/XDP kernel firewall dropping packet floods at NIC wire-speed |
| **[Caraka](https://github.com/koodoxz/caraka)** | Client / Edge | Zero-round-trip local proxy forwarding endpoint queries over DoQ |
| **[Gapura](https://github.com/koodoxz/gapura)** | Ingress Gateway | Public entry portal terminating DoH, DoT, and DoQ with token-bucket rate limiting |
| **[Runut](https://github.com/koodoxz/runut)** | Layer 7 (DNS Core) | High-performance zero-GC recursive root resolver |
| **[Tameng](https://github.com/koodoxz/tameng)** | Layer 7 (Application) | Autonomous ML-assisted Web Application Firewall & threat intelligence hub |
| **[Architecture Portal](https://koodoxz.github.io)** | Web Overview | Interactive architectural pipeline visualization and telemetry specs |

---

## Architecture & Subsystems

Kalas is split into two specialized Rust tiers:

```
┌─────────────────────────────────────────────────────────────┐
│                 USERSPACE AGENT (heimdall)                  │
│  - Prometheus metrics (:9090)                               │
│  - Dynamic blocklist synchronizer                           │
│  - Automated circuit breaker & telemetry logging            │
└──────────────────────────────┬──────────────────────────────┘
                               │ eBPF Maps Management
┌──────────────────────────────▼──────────────────────────────┐
│             KERNEL PERIMETER SUBSTRATE (eBPF / XDP)         │
│  - Native NIC driver hook (XDP_DRV mode)                    │
│  - Lock-free Per-CPU LRU Hash Maps                          │
│  - Sub-microsecond packet verdict (XDP_DROP / XDP_PASS)     │
└─────────────────────────────────────────────────────────────┘
```

- **`heimdall-xdp-ebpf`**: The pure kernel program compiled to eBPF bytecode. Attaches to the network driver hook (`XDP_DRV`) to inspect IP (L3) and TCP/UDP (L4) headers at line rate.
- **`heimdall-xdp`**: Userspace loader and type bindings interfacing with Linux kernel BPF subsystems via the `aya` framework.
- **`heimdall`**: The background supervision daemon that manages eBPF maps, evaluates traffic rate thresholds, handles dynamic sync with [Tameng](https://github.com/koodoxz/tameng), and exposes Prometheus metrics.

---

## Core Capabilities

- **Wire-Speed Volumetric Discard**: Rejects malicious traffic via `XDP_DROP` before memory allocation in Linux kernel networking buffers.
- **SYN Flood Tracking & Mitigation**: Tracks half-open TCP connections in per-CPU hash maps, enforcing strict connection-rate ceilings per IP subnet.
- **Port Reconnaissance Neutralization**: Detects and drops rapid sequential and distributed port-scanning sweeps.
- **Dynamic Threat Map Synchronization**: Receives real-time IP blacklists from [Tameng](https://github.com/koodoxz/tameng) L7 WAF and updates eBPF map tables atomically without service interruption.
- **AF_XDP Zero-Copy Ingestion**: Capable of bypassing standard kernel networking to stream raw DNS frames directly into userspace resolvers via shared memory ring buffers.
- **Failsafe Circuit Breaker**: Evaluates aggregate drop ratios; if anomalies threaten legitimate network reachability, the supervisor automatically enters a failsafe passive state.
- **Prometheus Telemetry**: Real-time metrics tracking dropped packets, passed frames, byte volume, and eBPF map saturation.

---

## Configuration Reference

Kalas daemon configuration (`configs/heimdall.yaml`):

```yaml
# Network Interface to attach XDP hook
interface: "eth0"
xdp_mode: "driver"             # driver (native) | generic (fallback)

# Protection Thresholds
syn_flood:
  enabled: true
  max_syn_per_second: 1000
  burst_limit: 2500

udp_flood:
  enabled: true
  max_udp_per_second: 5000

port_scan:
  enabled: true
  threshold_ports: 20
  window_seconds: 5

# Threat Intelligence Feed Integration
threat_intel:
  enabled: true
  sync_interval_secs: 10
  source: "tameng"              # Tameng dynamic feed sync

# Metrics Exporter
metrics:
  enabled: true
  bind_address: "127.0.0.1:9100"
```

---

## Build & Deployment

### Prerequisites
- Linux Kernel 5.15+ (with eBPF & XDP driver support)
- Rust nightly toolchain (required for `bpf-linker`)
- Clang / LLVM 15+

### Compiling Kernel Bytecode & Userspace Daemon
```bash
# Clone the repository
git clone https://github.com/koodoxz/kalas.git
cd kalas

# Compile eBPF program and userspace daemon
./build.sh
```

### Running Kalas
```bash
# Run with root privileges to attach XDP hook
sudo ./target/release/heimdall --config configs/heimdall.yaml
```

---

## License

Licensed under the GNU Affero General Public License v3.0 or later ([AGPL-3.0-or-later](LICENSE)).
