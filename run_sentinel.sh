#!/bin/bash
# Twinthos AI Security Sentinel — hourly feed check
cd "$(dirname "$0")"
python3 ai_sec_sentinel.py --since-hours 1 --feed-limit 50 >> /var/log/ai-sec-sentinel.log 2>&1
