# Simple Firewall Log Analyzer

A Python-based command-line tool to **parse and analyze firewall logs** from:

- 🪟 **Windows Defender Firewall** (`pfirewall.log`)
- 🐧 **Linux UFW / iptables** logs (with `SRC=`, `DST=`, `PROTO=`, `SPT=`, `DPT=`)

It provides:

- Action summary (ALLOW / DROP / BLOCK)
- Top source IPs and destination ports
- Protocol usage (TCP/UDP/etc.)
- Suspicious IP detection based on repeated blocked attempts
- CSV export for raw events and summary statistics

---

## 1. Features

- ✅ Supports **two major log formats**:
  - Windows Firewall (`pfirewall.log`)
  - UFW / iptables-style logs
- ✅ Automatically detects **log format** (Windows vs UFW/iptables)
- ✅ Extracts:
  - Timestamp
  - Source IP / Destination IP
  - Source port / Destination port
  - Protocol
  - Action (ALLOW/DROP/BLOCK/UNKNOWN)
- ✅ Highlights **blocked/denied** traffic
- ✅ Simple **IP classification** (private, external, loopback, etc.) for suspicious IPs
- ✅ Exports:
  - **Raw events** to CSV (`--export`)
  - **Summary stats** to CSV (`--export-summary`)
- ✅ Optional **colored terminal output** via `colorama`

---

## 2. Requirements

- **Python**: 3.10+ (tested with 3.12)
- Standard library only, plus optional:

```bash
pip install colorama
