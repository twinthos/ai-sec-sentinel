#!/bin/bash
# Install Twinthos Sentinel as a hourly cron job
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CRON_CMD="0 * * * * cd $SCRIPT_DIR && /usr/bin/python3 ai_sec_sentinel.py --since-hours 1 --feed-limit 50 >> /var/log/ai-sec-sentinel.log 2>&1"

# Add to crontab if not present
if ! crontab -l 2>/dev/null | grep -q 'ai-sec-sentinel'; then
    (crontab -l 2>/dev/null; echo "# Twinthos Sentinel"; echo "$CRON_CMD") | crontab -
    echo "Cron job installed — runs every hour"
else
    echo "Cron job already present"
fi

echo "Current crontab:"
crontab -l
