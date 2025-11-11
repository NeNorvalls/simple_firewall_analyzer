import os
import webbrowser
import subprocess

# Configuration
LOG_FILES = ["windows_sample.log"]  # add more if you want
EVENTS_CSV = "auto_events.csv"
SUMMARY_CSV = "auto_summary.csv"
HTML_REPORT = "auto_report.html"

CMD = [
    "python", "firewall_analyzer.py",
    "--file", *LOG_FILES,
    "--export", EVENTS_CSV,
    "--export-summary", SUMMARY_CSV,
    "--html-report", HTML_REPORT,
    "-n", "10",
    "--block-threshold", "1"
]

print("Running analyzer...")
subprocess.run(CMD)
print(f"\nOpening {HTML_REPORT} ...")
webbrowser.open(f"file://{os.path.abspath(HTML_REPORT)}")
