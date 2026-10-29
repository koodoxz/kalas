#!/bin/bash
# Memory Monitor for HEIMDALL & MIMIR-RS
# Logs memory usage every 5 minutes
# Usage: nohup ./monitor-memory.sh &

LOG_FILE="${LOG_FILE:-${HOME:-/var/log}/memory-monitor.log}"

echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting memory monitor" >> "$LOG_FILE"

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Get HEIMDALL memory (RSS in KB)
    HEIMDALL_PID=$(pidof heimdall)
    if [ -n "$HEIMDALL_PID" ]; then
        HEIMDALL_MEM=$(ps -p $HEIMDALL_PID -o rss= | tr -d ' ')
        HEIMDALL_MEM_MB=$((HEIMDALL_MEM / 1024))
    else
        HEIMDALL_MEM_MB=0
    fi
    
    # Get MIMIR memory
    MIMIR_PID=$(pidof mimir)
    if [ -n "$MIMIR_PID" ]; then
        MIMIR_MEM=$(ps -p $MIMIR_PID -o rss= | tr -d ' ')
        MIMIR_MEM_MB=$((MIMIR_MEM / 1024))
    else
        MIMIR_MEM_MB=0
    fi
    
    # Get total system memory
    TOTAL_USED=$(free -m | awk '/Mem:/ {print $3}')
    SWAP_USED=$(free -m | awk '/Swap:/ {print $3}')
    
    echo "$TIMESTAMP | HEIMDALL: ${HEIMDALL_MEM_MB}MB | MIMIR: ${MIMIR_MEM_MB}MB | Total Used: ${TOTAL_USED}MB | Swap: ${SWAP_USED}MB" >> "$LOG_FILE"
    
    sleep 300  # 5 minutes
done
