#!/bin/bash
# HEIMDALL-RS Build Script
# Builds both eBPF and userspace components

set -e

echo "🔨 Building HEIMDALL-RS..."

# Check for bpf-linker
if ! command -v bpf-linker &> /dev/null; then
    echo "⚠️ bpf-linker not found. Installing..."
    cargo install bpf-linker
fi

# Build eBPF program
echo "📦 Building eBPF program..."
cd heimdall-xdp-ebpf
cargo +nightly build --release \
    -Z build-std=core \
    --target bpfel-unknown-none

# Copy eBPF object
mkdir -p ../target/bpf
cp target/bpfel-unknown-none/release/heimdall-xdp-ebpf ../target/bpf/

cd ..

# Build userspace
echo "📦 Building userspace agent..."
cargo build --release -p heimdall

echo ""
echo "✅ Build complete!"
echo ""
echo "Output files:"
echo "  - target/bpf/heimdall-xdp-ebpf (eBPF program)"
echo "  - target/release/heimdall (Userspace agent)"
echo ""
echo "Run with:"
echo "  sudo ./target/release/heimdall --interface eth0 --ebpf target/bpf/heimdall-xdp-ebpf"
