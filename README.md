# Kalas (KALAS)

> High-Speed Layer 3 & Layer 4 Kernel Packet Sentinel (eBPF / XDP)
> Autonomous perimeter defense, SYN-flood damping, and wire-speed packet filtering.

[![Rust](https://img.shields.io/badge/Rust-1.75+-000000?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/Linux-eBPF%20%7C%20XDP-orange.svg)](#architecture)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-Architecture%20Portal-00f2fe.svg)](https://koodoxz.github.io)

---

## Executive Summary

**Kalas** (from ancient root: "protective perimeter tie / border node") is an eBPF/XDP sentinel operating at Layer 3 (IP/ICMP) and Layer 4 (TCP/UDP). It discards malicious network traffic directly at the network interface card driver level (XDP_DROP) before packets consume CPU cycles in kernel network stacks or userspace applications.

## Key Features

- Wire-Speed Filtering: Direct packet filtering at driver layer using eBPF maps.
- SYN Flood Protection: Real-time tracking and rate-limiting of TCP handshake floods.
- Port Scan Interception: Flags and drops rapid sequential/distributed port reconnaissance.
- Automated Threat Feeds: Synchronizes blocklists with [Tameng](https://github.com/koodoxz/tameng) WAF.
- Failsafe Circuit Breaker: Automatically halts drops if abnormal drop rates threaten legitimate traffic.

## License

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
