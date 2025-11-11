# 🔹 Project Title: Simple Firewall Log Analyzer

This project is a Python-based command-line tool that analyzes and visualizes firewall log files.  
It supports both **Windows Firewall** and **UFW (Uncomplicated Firewall)** logs, converting raw network data into organized summaries and interactive dashboards.

---

## 🧩 1. Project Overview

The goal of this project is to simplify the process of reviewing and understanding firewall logs.  
Firewall logs often contain thousands of entries that are difficult to interpret manually.

The **Simple Firewall Log Analyzer** automates this process by:

- Extracting key information from raw logs,  
- Summarizing network activity such as blocked and allowed traffic, and  
- Presenting the results through both terminal reports and HTML visual dashboards.  

This tool is particularly useful for **system administrators, security analysts, or students studying network security**.

---

## ⚙️ 2. Technologies Used

The project is developed using **Python 3.12**, relying mainly on the **standard library**, which makes it lightweight and portable.

**Key modules include:**
- `argparse` – for handling command-line input and options  
- `re` – for parsing log files using regular expressions  
- `ipaddress` – for classifying IPs as private, external, or invalid  
- `csv` and `json` – for data export and embedding structured data  
- `datetime` – for timestamps in reports  
- `collections.Counter` – for counting repeated IPs, ports, and protocols  

**Optional components:**
- `Colorama` – adds colored output to terminal reports  
- `Chart.js` (via CDN) – used for creating interactive charts in HTML dashboards  

---

## 🧱 3. System Architecture and Components

The project consists of several main components that work together:

### a) Log Parsing
The program reads raw log files and identifies patterns from:
- **UFW / iptables (Linux)**  
- **Windows Firewall (Windows)**  

Using regular expressions, it extracts:
- Timestamps  
- Source and destination IP addresses  
- Source and destination ports  
- Protocol type (TCP, UDP, etc.)  
- Action taken (ALLOW, BLOCK, DROP, DENY)  

Each valid log entry is converted into a structured data dictionary for further processing.

---

### b) Filtering and Analysis
After parsing, the program allows filtering based on user input:
- Show only blocked traffic (`--only-blocked`)  
- Filter by protocol (`--proto TCP`)  
- Filter by source or destination IP  

It then analyzes and aggregates data using Python’s `Counter` to determine:
- The most frequent source IP addresses  
- The most targeted destination ports  
- Action distribution (ALLOW vs BLOCK/DROP)  
- Protocol usage statistics  

The analyzer also detects **suspicious IP addresses** that exceed a certain threshold of blocked attempts.

---

### c) Reporting and Visualization
The program supports multiple output formats:

**Terminal Report:**  
Displays key findings in the console with color-coded highlights for actions (e.g., red for BLOCKED, green for ALLOWED).

**CSV Export:**  
Generates two CSV files:  
- `events.csv` — containing all parsed entries  
- `summary.csv` — containing aggregated data summaries  

**HTML Dashboard:**  
Produces a fully formatted interactive dashboard that visualizes:
- Actions summary (ALLOW vs BLOCK)  
- Protocol usage  
- Top source IPs and destination ports  
- Suspicious IP addresses  

The HTML report uses **Chart.js** for dynamic, animated charts and includes a modern **dark theme** for readability.

---

## 💡 4. How the Program Works

The user runs the program from the terminal, for example:

- python firewall_analyzer.py --file windows_sample.log --html-report report.html

- The program reads one or more log files and extracts relevant entries.
- It applies the specified filters and counts key statistics.
- The results are printed in the terminal or exported as CSV and HTML files.
- The HTML report can then be opened in a browser to view graphical summaries of the analyzed data.

## 🧠 5. Advanced Features

### IP Classification:
- Determines if an IP is private, external, or loopback using the ipaddress module.

### Suspicious Activity Detection:
- Identifies IPs with excessive blocked attempts (default threshold: 20).

### External Reputation Integration (Planned):
- The project includes a placeholder function for integrating APIs such as VirusTotal or AbuseIPDB for real-world IP reputation checks.

## 📊 6. Example Output

### Example commands:
#### Basic Analysis:
- python firewall_analyzer.py --file windows_sample.log

#### With CSV Export:
- python firewall_analyzer.py --file windows_sample.log --export events.csv --export-summary summary.csv

#### With HTML Dashboard:
- python firewall_analyzer.py --file windows_sample.log --html-report auto_report.html
- 
#### Generated files:
- events.csv → all parsed entries
- summary.csv → summary statistics
- auto_report.html → interactive visual dashboard

## 🚀 7. Future Enhancements

### Planned improvements include:
- Integration of live IP reputation lookups through APIs
- Support for additional log formats such as pfSense and cloud-based firewalls
- Real-time monitoring through a web interface
- Docker containerization for easier deployment

## 📘 8. Conclusion
- The Simple Firewall Log Analyzer offers a practical and efficient solution for transforming complex firewall logs into clear, visual insights.
- It provides a complete analysis pipeline — from log parsing to visualization — all within a lightweight Python environment.

This tool can serve both as a security utility and a learning resource for understanding real-world network activity.