#!/usr/bin/env python3
"""
DOS Detection System
====================
Detects Denial of Service (DoS) attacks by monitoring network traffic
and identifying abnormal patterns indicative of an attack.

Author  : Mohamed Mosttafa
Task    : DOS Detection – The Sparks Foundation Internship
Date    : May 2026
Tools   : Python 3, Scapy
"""

import time
import threading
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list

# ── Configuration ────────────────────────────────────────────────────────────
INTERFACE        = "eth0"          # Network interface to monitor
WINDOW_SECONDS   = 5               # Time window for rate analysis (seconds)
LOG_FILE         = "dos_alerts.log"

# Thresholds – lower values for demo/testing purposes
THRESHOLD_SYN    = 5              # SYN packets per window → SYN Flood
THRESHOLD_ICMP   = 5             # ICMP packets per window → ICMP/Ping Flood
THRESHOLD_UDP    = 5              # UDP packets per window → UDP Flood
THRESHOLD_TOTAL  = 10             # Total packets per window → General DoS
THRESHOLD_IP     = 5              # Packets from single IP per window

# ── Counters (thread-safe via lock) ──────────────────────────────────────────
lock           = threading.Lock()
packet_count   = defaultdict(int)   # {src_ip: count}
syn_count      = defaultdict(int)   # {src_ip: syn_count}
icmp_count     = defaultdict(int)   # {src_ip: icmp_count}
udp_count      = defaultdict(int)   # {src_ip: udp_count}
total_packets  = [0]
alerts_raised  = []
start_time     = [time.time()]

COLORS = {
    "RED"    : "\033[91m",
    "YELLOW" : "\033[93m",
    "GREEN"  : "\033[92m",
    "CYAN"   : "\033[96m",
    "BOLD"   : "\033[1m",
    "RESET"  : "\033[0m",
}

def c(color, text):
    return f"{COLORS[color]}{text}{COLORS['RESET']}"

def log_alert(alert_type, src_ip, count, threshold):
    """Log an alert to console and file."""
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = (f"[{ts}] ALERT | {alert_type} | "
           f"Source IP: {src_ip} | "
           f"Count: {count} | Threshold: {threshold}")

    print(c("RED", f"\n{'='*65}"))
    print(c("RED",   f"  ⚠  ALERT DETECTED: {alert_type}"))
    print(c("YELLOW",f"  Source IP  : {src_ip}"))
    print(c("YELLOW",f"  Packet Cnt : {count}  (threshold: {threshold})"))
    print(c("YELLOW",f"  Timestamp  : {ts}"))
    print(c("RED",   f"{'='*65}\n"))

    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

    alerts_raised.append({
        "type": alert_type, "src": src_ip,
        "count": count, "threshold": threshold, "time": ts
    })

def analyze_packet(pkt):
    """Classify each captured packet and update counters."""
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src

    with lock:
        total_packets[0] += 1
        packet_count[src] += 1

        if pkt.haslayer(TCP):
            # SYN flag = 0x02, check for SYN-only (not SYN-ACK)
            flags = pkt[TCP].flags
            if flags == 0x02:
                syn_count[src] += 1

        if pkt.haslayer(ICMP):
            icmp_count[src] += 1

        if pkt.haslayer(UDP):
            udp_count[src] += 1

def check_thresholds():
    """Periodically check counters against thresholds and reset."""
    while True:
        time.sleep(WINDOW_SECONDS)

        with lock:
            elapsed = time.time() - start_time[0]
            ts      = datetime.now().strftime("%H:%M:%S")

            print(c("CYAN", f"\n[{ts}] ── Traffic Report (last {WINDOW_SECONDS}s) ──"))
            print(f"  Total packets  : {c('BOLD', str(total_packets[0]))}")
            print(f"  Unique sources : {c('BOLD', str(len(packet_count)))}")

            # Per-IP checks
            for ip in list(packet_count.keys()):

                # General per-IP flood
                if packet_count[ip] >= THRESHOLD_IP:
                    log_alert("IP Flood (General DoS)", ip,
                              packet_count[ip], THRESHOLD_IP)

                # SYN Flood
                if syn_count[ip] >= THRESHOLD_SYN:
                    log_alert("SYN Flood Attack", ip,
                              syn_count[ip], THRESHOLD_SYN)

                # ICMP / Ping Flood
                if icmp_count[ip] >= THRESHOLD_ICMP:
                    log_alert("ICMP/Ping Flood Attack", ip,
                              icmp_count[ip], THRESHOLD_ICMP)

                # UDP Flood
                if udp_count[ip] >= THRESHOLD_UDP:
                    log_alert("UDP Flood Attack", ip,
                              udp_count[ip], THRESHOLD_UDP)

                # Show per-IP stats if any traffic
                if packet_count[ip] > 0:
                    print(f"  {ip:<18} total={packet_count[ip]:<6} "
                          f"syn={syn_count[ip]:<5} "
                          f"icmp={icmp_count[ip]:<5} "
                          f"udp={udp_count[ip]:<5}")

            # General volume check
            if total_packets[0] >= THRESHOLD_TOTAL:
                log_alert("High Volume DoS Attack", "NETWORK",
                          total_packets[0], THRESHOLD_TOTAL)

            if not alerts_raised:
                print(c("GREEN", "  Status: No threats detected."))
            else:
                print(c("RED", f"  Status: {len(alerts_raised)} alert(s) raised!"))

            # Reset counters for next window
            packet_count.clear()
            syn_count.clear()
            icmp_count.clear()
            udp_count.clear()
            total_packets[0] = 0

def print_banner():
    print(c("CYAN", """
╔══════════════════════════════════════════════════════════╗
║           DoS Detection System v1.0                     ║
║   The Sparks Foundation Internship – Mohamed Mosttafa   ║
╚══════════════════════════════════════════════════════════╝
"""))
    print(f"  Interface : {c('BOLD', INTERFACE)}")
    print(f"  Window    : {c('BOLD', str(WINDOW_SECONDS))} seconds")
    print(f"  Thresholds:")
    print(f"    SYN Flood   : {THRESHOLD_SYN} pkts/window")
    print(f"    ICMP Flood  : {THRESHOLD_ICMP} pkts/window")
    print(f"    UDP Flood   : {THRESHOLD_UDP} pkts/window")
    print(f"    Total DoS   : {THRESHOLD_TOTAL} pkts/window")
    print(f"    Per-IP      : {THRESHOLD_IP} pkts/window")
    print(f"\n  Log file  : {c('BOLD', LOG_FILE)}")
    print(c("GREEN", "\n  Monitoring started. Press Ctrl+C to stop.\n"))

def print_summary():
    print(c("CYAN", "\n\n── Final Session Summary ──────────────────────────────"))
    if not alerts_raised:
        print(c("GREEN", "  No DoS attacks detected during this session."))
    else:
        print(c("RED", f"  Total alerts raised: {len(alerts_raised)}"))
        for a in alerts_raised:
            print(f"  [{a['time']}] {a['type']} | {a['src']} | {a['count']} pkts")
    print(c("CYAN", "────────────────────────────────────────────────────────\n"))

if __name__ == "__main__":
    print_banner()

    # Start threshold checker in background thread
    checker = threading.Thread(target=check_thresholds, daemon=True)
    checker.start()

    try:
        sniff(iface=INTERFACE, prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print_summary()
    except PermissionError:
        print(c("RED", "\n  Error: Run with sudo: sudo python3 dos_detector.py"))
    except Exception as e:
        print(c("RED", f"\n  Error: {e}"))
