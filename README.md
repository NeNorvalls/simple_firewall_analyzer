# 🔥 Simple Firewall Log Analyzer

A powerful Python-based **firewall log analyzer and visual dashboard**.  
It parses, summarizes, and visualizes firewall activity from log files — supporting both **Windows Firewall** and **UFW-style** logs.

---

## 🚀 Features

✅ **Multi-log analysis** — analyze multiple log files at once  
✅ **Protocol & action statistics** — detect ALLOW / DROP / BLOCK events  
✅ **Top source IPs & destination ports** — quick insight into traffic  
✅ **Suspicious IP detection** — flags repeated block attempts  
✅ **CSV export** — for further analysis or archival  
✅ **Interactive HTML Dashboard** — Chart.js-based visualization with animations  
✅ **Dark theme report** — modern UI with dynamic colors  
✅ **Optional auto-open in browser** — instantly view generated dashboards  

---

## 🧰 Requirements

- Python 3.12 or newer  
- No external dependencies required (uses only built-in modules)

## For HTML charts:
- Internet access for Chart.js (loaded via CDN)

---
## Basic Command
- python firewall_analyzer.py --file windows_sample.log

##🔹 With CSV Export
- python firewall_analyzer.py --file windows_sample.log \
  --export events.csv \
  --export-summary summary.csv

##🔹 With HTML Dashboard
- python firewall_analyzer.py --file windows_sample.log \
  --html-report auto_report.html


## This generates:
- events.csv — raw parsed event data
- summary.csv — summary stats (actions, IPs, ports)
- auto_report.html — interactive dashboard viewable in any browser

## 🌐 HTML Dashboard
The HTML dashboard (auto_report.html) includes:
- 📊 Charts (Chart.js)
- Actions summary (ALLOW vs DROP)
- Protocol usage (TCP vs UDP)
- Top source IPs
- Top destination ports
- 🕶️ Dark Mode
- 🎨 Animated transitions
- 🕓 Auto-generated timestamp

## Supported Log Formats
Format	Example Source
- Windows Firewall	C:\Windows\System32\LogFiles\Firewall\pfirewall.log
- UFW / iptables (Linux)	/var/log/ufw.log

## Advanced Usage
- python firewall_analyzer.py \
  --file windows_sample.log another_log.log \
  --export merged_events.csv \
  --export-summary merged_summary.csv \
  --html-report auto_report.html \
  -n 5 --block-threshold 1