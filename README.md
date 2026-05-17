# DoS Detection System

## Overview
A Python-based Denial of Service (DoS) detection system that monitors network traffic and identifies attack patterns in real time.

## Features
- SYN Flood detection
- ICMP/Ping Flood detection
- UDP Flood detection
- General high-volume DoS detection
- Per-IP traffic analysis
- Real-time alerting with colored terminal output
- Alert logging to dos_alerts.log

## Tools
- Python 3 | Scapy | Kali Linux | hping3

## Results
- 7 alerts successfully detected during testing
- 0 false positives
- Detection latency under 5 seconds

## Usage
```bash
sudo python3 dos_detector.py
```

## Author
Mohamed Mosttafa | May 2026
