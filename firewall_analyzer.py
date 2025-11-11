import argparse
import re
import sys
import csv
import ipaddress
import json
from datetime import datetime
from collections import Counter
from html import escape as html_escape

# --- Optional colors (colorama) ---------------------------------------

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init()

    def green(text):
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}"

    def red(text):
        return f"{Fore.RED}{text}{Style.RESET_ALL}"

    def yellow(text):
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"

    def cyan(text):
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}"

except ImportError:  # fall back to plain text if colorama not installed

    def green(text):
        return text

    def red(text):
        return text

    def yellow(text):
        return text

    def cyan(text):
        return text


# --- Patterns ---------------------------------------------------------

# UFW / iptables-style lines (with SRC= / DST= / PROTO= / SPT= / DPT=)
LOG_PATTERN = re.compile(
    r"SRC=(?P<src>\d+\.\d+\.\d+\.\d+)\s+"
    r"DST=(?P<dst>\d+\.\d+\.\d+\.\d+).*?"
    r"PROTO=(?P<proto>\w+).*?"
    r"SPT=(?P<sport>\d+)\s+"
    r"DPT=(?P<dport>\d+)"
)

# Example: [UFW BLOCK] or [UFW ALLOW]
ACTION_PATTERN = re.compile(
    r"\[(?P<tag>\w+)\s+(?P<action>\w+)\]"
)

# UFW / iptables timestamp at the start of the line, e.g. "Jan 10 12:00:01"
UFW_TS_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)


# --- Small "IP reputation" helpers ------------------------------------


def classify_ip(ip_str: str) -> str:
    """
    Offline/simple IP classification using Python's ipaddress module.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid"

    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    return "external"


def external_ip_reputation(ip_str: str):
    """
    Placeholder for real IP reputation lookup via external API.

    You can integrate services here (VirusTotal, AbuseIPDB, etc.).
    By default, it returns None and is NOT calling anything.
    """
    # Example skeleton (commented out to avoid errors):
    # import requests
    # API_KEY = "YOUR_API_KEY_HERE"
    # url = f"https://example.com/ip-reputation/{ip_str}?key={API_KEY}"
    # try:
    #     resp = requests.get(url, timeout=3)
    #     if resp.ok:
    #         data = resp.json()
    #         return data.get("reputation", "unknown")
    # except Exception:
    #     return None
    return None


# --- Parsing ----------------------------------------------------------


def parse_log_line(line: str):
    """
    Parse a single firewall log line (UFW or Windows).

    Returns:
        dict with keys:
        - timestamp (str)
        - src, dst (str)
        - proto (str)
        - sport, dport (str)
        - action (str)
        - source (str)  -> "UFW/IPTABLES" or "WINDOWS_FIREWALL"
        or None if the line doesn't match a supported pattern.
    """
    # 1) Try UFW / iptables style first
    m = LOG_PATTERN.search(line)
    if m:
        data = m.groupdict()

        # Try to extract timestamp from the start (best-effort)
        ts_match = UFW_TS_PATTERN.match(line)
        if ts_match:
            ts = f"{ts_match.group('month')} {ts_match.group('day')} {ts_match.group('time')}"
        else:
            ts = ""

        # Default if we can't detect the action
        action = "UNKNOWN"
        am = ACTION_PATTERN.search(line)
        if am:
            action = am.group("action").upper()

        data["action"] = action
        data["timestamp"] = ts
        data["source"] = "UFW/IPTABLES"
        return data

    # 2) Try Windows Firewall log format
    # Skip comments / header lines starting with '#'
    if line.lstrip().startswith("#"):
        return None

    parts = line.split()
    # Expected at least: date time action protocol src-ip dst-ip src-port dst-port
    if len(parts) >= 8:
        date, time_, action, proto, src_ip, dst_ip, src_port, dst_port = parts[:8]
        action = action.upper()

        if action in {"ALLOW", "DROP", "BLOCK"}:
            return {
                "timestamp": f"{date} {time_}",
                "src": src_ip,
                "dst": dst_ip,
                "proto": proto.upper(),
                "sport": src_port,
                "dport": dst_port,
                "action": action,
                "source": "WINDOWS_FIREWALL",
            }

    # If nothing matched, skip this line
    return None


# --- Filter logic -----------------------------------------------------


def entry_matches_filters(entry: dict, filters: dict) -> bool:
    """
    Apply CLI filters to a parsed log entry.
    Filters:
      - only_blocked (bool)
      - proto (str or None)
      - src_ip (str or None)
      - dst_ip (str or None)
    """
    action = entry["action"].upper()
    proto = entry["proto"].upper()

    if filters.get("only_blocked"):
        if action not in {"BLOCK", "DROP", "DENY"}:
            return False

    proto_filter = filters.get("proto")
    if proto_filter and proto != proto_filter.upper():
        return False

    src_filter = filters.get("src_ip")
    if src_filter and entry["src"] != src_filter:
        return False

    dst_filter = filters.get("dst_ip")
    if dst_filter and entry["dst"] != dst_filter:
        return False

    return True


# --- Analysis (supports multiple files) -------------------------------


def analyze_logs(file_paths, filters: dict):
    """
    Read one or more log files and build combined statistics.

    file_paths: list of path strings
    filters: dict of filter settings
    """
    src_counter = Counter()
    dport_counter = Counter()
    proto_counter = Counter()
    action_counter = Counter()
    blocked_by_src = Counter()
    source_counter = Counter()  # which log formats we saw

    total_lines = 0
    parsed_lines = 0
    parsed_entries = []

    for path in file_paths:
        try:
            f = open(path, "r", errors="ignore")
        except FileNotFoundError:
            print(red(f"[WARN] Log file not found: {path}"), file=sys.stderr)
            continue
        except PermissionError:
            print(red(f"[WARN] Permission denied when reading: {path}"), file=sys.stderr)
            continue

        with f:
            for line in f:
                total_lines += 1
                parsed = parse_log_line(line)
                if not parsed:
                    continue

                if not entry_matches_filters(parsed, filters):
                    continue

                parsed_lines += 1
                src = parsed["src"]
                dport = parsed["dport"]
                proto = parsed["proto"]
                action = parsed["action"]

                src_counter[src] += 1
                dport_counter[dport] += 1
                proto_counter[proto] += 1
                action_counter[action] += 1
                source_counter[parsed["source"]] += 1

                if action in {"BLOCK", "DENY", "DROP"}:
                    blocked_by_src[src] += 1

                parsed_entries.append(parsed)

    return {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "src_counter": src_counter,
        "dport_counter": dport_counter,
        "proto_counter": proto_counter,
        "action_counter": action_counter,
        "blocked_by_src": blocked_by_src,
        "parsed_entries": parsed_entries,
        "source_counter": source_counter,
        "filters": filters,
    }


# --- Reporting (terminal) ---------------------------------------------


def print_report(stats, top_n: int, block_threshold: int):
    print(f"\nTotal lines in file(s): {stats['total_lines']}")
    print(f"Successfully parsed (after filters): {stats['parsed_lines']}\n")

    # Show filters used
    filters = stats.get("filters", {})
    active_filters = []
    if filters.get("only_blocked"):
        active_filters.append("only_blocked")
    if filters.get("proto"):
        active_filters.append(f"proto={filters['proto']}")
    if filters.get("src_ip"):
        active_filters.append(f"src_ip={filters['src_ip']}")
    if filters.get("dst_ip"):
        active_filters.append(f"dst_ip={filters['dst_ip']}")
    if active_filters:
        print("Active filters: " + ", ".join(active_filters) + "\n")

    # Log format detection
    if stats["source_counter"]:
        print("Log formats detected:")
        for src, count in stats["source_counter"].most_common():
            print(f"  {src}: {count} entries")
        print()

    # Actions summary
    print("Actions summary:")
    for action, count in stats["action_counter"].most_common():
        label = action
        if action in {"BLOCK", "DROP", "DENY"}:
            label = red(action)
        elif action == "ALLOW":
            label = green(action)
        print(f"  {label}: {count}")
    print()

    # Top source IPs
    print(f"Top {top_n} Source IPs:")
    for ip, count in stats["src_counter"].most_common(top_n):
        print(f"  {ip:15}  {count} hits")
    print()

    # Top destination ports
    print(f"Top {top_n} Destination Ports:")
    for port, count in stats["dport_counter"].most_common(top_n):
        print(f"  {port:5}  {count} hits")
    print()

    # Protocol usage
    print("Protocol Usage:")
    for proto, count in stats["proto_counter"].most_common():
        print(f"  {proto}: {count} entries")
    print()

    # Suspicious IPs
    if stats["blocked_by_src"]:
        print(
            f"Suspicious IPs (>= {block_threshold} blocked attempts)"
            f" {yellow('(with simple reputation + optional external hook)')}:"
        )
        found_any = False
        for ip, count in stats["blocked_by_src"].most_common():
            if count >= block_threshold:
                rep = classify_ip(ip)
                ext_rep = external_ip_reputation(ip)
                rep_str = rep
                if ext_rep:
                    rep_str += f", external={ext_rep}"
                line = f"{ip:15}  {count} blocked hits  [{rep_str}]"
                print("  " + red("⚠ " + line))
                found_any = True
        if not found_any:
            print("  (none at this threshold)")
    else:
        print("No blocked entries recorded.")


# --- CSV Exports ------------------------------------------------------


def export_events_to_csv(stats, filename):
    """
    Write parsed log entries to a CSV file.

    Columns:
    - timestamp
    - src, dst
    - proto
    - sport, dport
    - action
    - source (UFW/IPTABLES or WINDOWS_FIREWALL)
    """
    if not stats["parsed_entries"]:
        print("[WARN] No parsed entries to export.")
        return

    fieldnames = [
        "timestamp",
        "src",
        "dst",
        "proto",
        "sport",
        "dport",
        "action",
        "source",
    ]

    with open(filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(stats["parsed_entries"])

    print(f"\n{green('Exported')} {len(stats['parsed_entries'])} entries to {filename}")


def export_summary_to_csv(stats, filename, top_n: int, block_threshold: int):
    """
    Export summary stats (top IPs, ports, actions, suspicious IPs) to CSV.
    """
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(["Section", "Key", "Value"])

        # Actions
        writer.writerow(["Actions", "Action", "Count"])
        for action, count in stats["action_counter"].most_common():
            writer.writerow(["ACTION", action, count])
        writer.writerow([])

        # Top source IPs
        writer.writerow(["Top Source IPs", "IP", "Hits"])
        for ip, count in stats["src_counter"].most_common(top_n):
            writer.writerow(["TOP_SRC", ip, count])
        writer.writerow([])

        # Top destination ports
        writer.writerow(["Top Destination Ports", "Port", "Hits"])
        for port, count in stats["dport_counter"].most_common(top_n):
            writer.writerow(["TOP_DPORT", port, count])
        writer.writerow([])

        # Suspicious
        writer.writerow(
            [f"Suspicious IPs (>= {block_threshold} blocked)", "IP", "Blocked Hits / Rep"]
        )
        any_suspicious = False
        for ip, count in stats["blocked_by_src"].most_common():
            if count >= block_threshold:
                rep = classify_ip(ip)
                writer.writerow(
                    ["SUSPICIOUS", ip, f"{count} (rep={rep})"]
                )
                any_suspicious = True
        if not any_suspicious:
            writer.writerow(["SUSPICIOUS", "(none)", "0"])

    print(f"{green('Exported summary')} to {filename}")


# --- HTML Report with Chart.js ----------------------------------------


def export_html_report(stats, filename, top_n: int, block_threshold: int):
    """
    Generate an HTML dashboard report with charts using Chart.js.
    """

    def esc(s):
        return html_escape(str(s))

    # Optional logo URL or file (leave empty for none)
    logo_url = ""  # e.g. "logo.png" or "https://example.com/logo.png"

    # Prepare data for charts
    actions = stats["action_counter"]
    protocols = stats["proto_counter"]
    top_src = stats["src_counter"].most_common(top_n)
    top_dports = stats["dport_counter"].most_common(top_n)

    actions_labels = list(actions.keys())
    actions_values = list(actions.values())

    proto_labels = list(protocols.keys())
    proto_values = list(protocols.values())

    src_labels = [ip for ip, _ in top_src]
    src_values = [count for _, count in top_src]

    dport_labels = [port for port, _ in top_dports]
    dport_values = [count for _, count in top_dports]

    # Filters string
    filters = stats.get("filters", {})
    active_filters = []
    if filters.get("only_blocked"):
        active_filters.append("only_blocked")
    if filters.get("proto"):
        active_filters.append(f"proto={filters['proto']}")
    if filters.get("src_ip"):
        active_filters.append(f"src_ip={filters['src_ip']}")
    if filters.get("dst_ip"):
        active_filters.append(f"dst_ip={filters['dst_ip']}")

    # Suspicious IPs
    suspicious_rows = []
    for ip, count in stats["blocked_by_src"].most_common():
        if count >= block_threshold:
            rep = classify_ip(ip)
            ext_rep = external_ip_reputation(ip)
            rep_str = rep
            if ext_rep:
                rep_str += f", external={ext_rep}"
            suspicious_rows.append((ip, count, rep_str))

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_parts = []
    html_parts.append("<!DOCTYPE html>")
    html_parts.append("<html><head><meta charset='utf-8'><title>Firewall Report</title>")
    html_parts.append("<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>")
    html_parts.append(
        "<style>"
        "body{font-family:Arial, sans-serif;background:#111;color:#eee;padding:20px;}"
        "h1,h2,h3{color:#4caf50;}"
        "table{border-collapse:collapse;margin-bottom:20px;width:100%;max-width:1000px;}"
        "th,td{border:1px solid #444;padding:6px 8px;font-size:0.9rem;text-align:left;}"
        "th{background:#222;}"
        "tr:nth-child(even){background:#181818;}"
        ".badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:0.8rem;}"
        ".allow{background:#2e7d32;color:#fff;}"
        ".block{background:#c62828;color:#fff;}"
        ".meta{color:#aaa;font-size:0.9rem;}"
        ".layout{display:flex;flex-wrap:wrap;gap:24px;margin-top:10px;}"
        ".card{background:#121212;border:1px solid #333;border-radius:10px;padding:12px;flex:1 1 300px;}"
        "canvas{max-width:100%;height:260px !important;}"
        "footer{margin-top:30px;font-size:0.8rem;color:#777;}"
        "</style></head><body>"
    )

    # Header
    html_parts.append("<header style='display:flex;align-items:center;gap:16px;margin-bottom:20px;'>")
    if logo_url:
        html_parts.append(
            f"<img src='{esc(logo_url)}' alt='Logo' style='height:48px;width:auto;border-radius:8px;'>"
        )
    html_parts.append("<div>")
    html_parts.append("<h1>Simple Firewall Log Analyzer</h1>")
    html_parts.append(
        f"<p class='meta'>Total lines in file(s): {esc(stats['total_lines'])}<br>"
        f"Successfully parsed (after filters): {esc(stats['parsed_lines'])}</p>"
    )
    if active_filters:
        html_parts.append(
            "<p class='meta'>Active filters: " + esc(", ".join(active_filters)) + "</p>"
        )
    html_parts.append("</div></header>")

    # Log formats detected
    if stats["source_counter"]:
        html_parts.append("<h2>Log formats detected</h2>")
        html_parts.append("<table><tr><th>Source</th><th>Entries</th></tr>")
        for src, count in stats["source_counter"].most_common():
            html_parts.append(f"<tr><td>{esc(src)}</td><td>{esc(count)}</td></tr>")
        html_parts.append("</table>")

    # Charts layout
    html_parts.append("<div class='layout'>")

    # Actions chart
    html_parts.append("<div class='card'><h2>Actions summary</h2>")
    html_parts.append("<canvas id='actionsChart'></canvas></div>")

    # Protocols chart
    html_parts.append("<div class='card'><h2>Protocol usage</h2>")
    html_parts.append("<canvas id='protocolsChart'></canvas></div>")

    # Top source IPs chart
    html_parts.append("<div class='card'><h2>Top source IPs</h2>")
    html_parts.append("<canvas id='srcChart'></canvas></div>")

    # Top destination ports chart
    html_parts.append("<div class='card'><h2>Top destination ports</h2>")
    html_parts.append("<canvas id='dportChart'></canvas></div>")

    html_parts.append("</div>")  # end layout

    # Suspicious IPs table
    html_parts.append(
        f"<h2>Suspicious IPs (≥ {esc(block_threshold)} blocked attempts)</h2>"
    )
    html_parts.append("<table><tr><th>IP</th><th>Blocked Hits</th><th>Reputation</th></tr>")
    if suspicious_rows:
        for ip, count, rep_str in suspicious_rows:
            html_parts.append(
                f"<tr><td>{esc(ip)}</td><td>{esc(count)}</td><td>{esc(rep_str)}</td></tr>"
            )
    else:
        html_parts.append(
            "<tr><td colspan='3' class='meta'>(none at this threshold)</td></tr>"
        )
    html_parts.append("</table>")

    # Footer
    html_parts.append(
        f"<footer>Report generated at {esc(generated_at)}</footer>"
    )

    # JS data for charts
    html_parts.append("<script>")
    html_parts.append(f"const actionsLabels = {json.dumps(actions_labels)};")
    html_parts.append(f"const actionsValues = {json.dumps(actions_values)};")
    html_parts.append(f"const protoLabels = {json.dumps(proto_labels)};")
    html_parts.append(f"const protoValues = {json.dumps(proto_values)};")
    html_parts.append(f"const srcLabels = {json.dumps(src_labels)};")
    html_parts.append(f"const srcValues = {json.dumps(src_values)};")
    html_parts.append(f"const dportLabels = {json.dumps(dport_labels)};")
    html_parts.append(f"const dportValues = {json.dumps(dport_values)};")

    html_parts.append(
        """
// Helper to generate a palette of colors
function generateColors(n) {
  const baseColors = [
    '#4caf50','#ff9800','#2196f3','#e91e63','#9c27b0',
    '#00bcd4','#ffc107','#03a9f4','#8bc34a','#f44336'
  ];
  const colors = [];
  for (let i = 0; i < n; i++) {
    colors.push(baseColors[i % baseColors.length]);
  }
  return colors;
}

function createChart(ctxId, type, labels, data, optionsExtra) {
  const canvas = document.getElementById(ctxId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!labels.length) return;

  const colors = generateColors(labels.length);
  return new Chart(ctx, {
    type: type,
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: colors,
        borderColor: '#111',
        borderWidth: 1,
      }]
    },
    options: Object.assign({
      responsive: true,
      maintainAspectRatio: false,
      animation: {
        duration: 900,
        easing: 'easeOutCubic'
      },
      plugins: {
        legend: {
          labels: {
            color: '#eee'
          }
        }
      },
      scales: {
        x: {
          ticks: { color: '#ddd' },
          grid: { color: '#333' }
        },
        y: {
          ticks: { color: '#ddd' },
          grid: { color: '#333' },
          beginAtZero: true
        }
      }
    }, optionsExtra || {})
  });
}

window.addEventListener('load', () => {
  createChart('actionsChart', 'doughnut', actionsLabels, actionsValues, {
    plugins: {
      legend: { position: 'bottom', labels: { color: '#eee' } }
    },
    scales: {}
  });

  createChart('protocolsChart', 'pie', protoLabels, protoValues, {
    plugins: {
      legend: { position: 'bottom', labels: { color: '#eee' } }
    },
    scales: {}
  });

  createChart('srcChart', 'bar', srcLabels, srcValues, {
    indexAxis: 'y',
    plugins: { legend: { display: false } }
  });

  createChart('dportChart', 'bar', dportLabels, dportValues, {
    plugins: { legend: { display: false } }
  });
});
"""
    )
    html_parts.append("</script>")
    html_parts.append("</body></html>")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))

    print(green(f"Exported HTML report to {filename}"))


# --- CLI --------------------------------------------------------------


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Simple Firewall Log Analyzer (UFW + Windows firewall) "
                    "with filters, CSV export, and HTML report."
    )
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        nargs="+",
        help="Path(s) to firewall log file(s) (space-separated for multiple)",
    )
    parser.add_argument(
        "-n",
        "--top",
        type=int,
        default=10,
        help="Top N IPs/ports to show (default: 10)",
    )
    parser.add_argument(
        "--block-threshold",
        type=int,
        default=20,
        help="Min blocked attempts to mark IP as suspicious (default: 20)",
    )
    parser.add_argument(
        "--only-blocked",
        action="store_true",
        help="Analyze only blocked / dropped / denied entries",
    )
    parser.add_argument(
        "--proto",
        help="Filter by protocol (e.g. TCP, UDP)",
    )
    parser.add_argument(
        "--src-ip",
        help="Filter by exact source IP",
    )
    parser.add_argument(
        "--dst-ip",
        help="Filter by exact destination IP",
    )
    parser.add_argument(
        "--export",
        metavar="CSV_FILE",
        help="Export all parsed events to a CSV file",
    )
    parser.add_argument(
        "--export-summary",
        metavar="CSV_FILE",
        help="Export aggregated summary stats to CSV",
    )
    parser.add_argument(
        "--html-report",
        metavar="HTML_FILE",
        help="Export an HTML dashboard-style report",
    )
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    filters = {
        "only_blocked": args.only_blocked,
        "proto": args.proto,
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
    }

    stats = analyze_logs(args.file, filters)

    if stats["total_lines"] == 0:
        print(red("[ERROR] No lines read from the provided file(s)."), file=sys.stderr)
        sys.exit(1)

    print_report(stats, top_n=args.top, block_threshold=args.block_threshold)

    if args.export:
        export_events_to_csv(stats, args.export)

    if args.export_summary:
        export_summary_to_csv(
            stats,
            args.export_summary,
            top_n=args.top,
            block_threshold=args.block_threshold,
        )

    if args.html_report:
        export_html_report(
            stats,
            args.html_report,
            top_n=args.top,
            block_threshold=args.block_threshold,
        )


if __name__ == "__main__":
    main()
