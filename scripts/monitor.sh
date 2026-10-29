#!/bin/bash
# HEIMDALL + MIMIR Stability Monitor

LOG=/opt/heimdall/stability.log
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# XDP Status
XDP_ID=$(ip link show eth0 | grep 'prog/xdp id' | awk '{print $3}')

# DNS Test
DNS_OK=$(dig @127.0.0.1 google.com +short +timeout=2 | head -1)

# HEIMDALL Metrics
METRICS=$(curl -s localhost:9091/metrics 2>/dev/null | grep -E 'heimdall_(blocked|syn_flood|port_scan)_total' | tr '\n' ' ')

# MIMIR-RS Status  
MIMIR_OK=$(curl -s localhost:9153/metrics 2>/dev/null | grep -c 'mimir_' || echo 0)

echo "[$TIMESTAMP] XDP=$XDP_ID | DNS=${DNS_OK:-FAIL} | MIMIR=$MIMIR_OK | $METRICS" >> $LOG
tail -1 $LOG
