"""
Network Security and Firewall Monitoring System  (CSA0712)

A small, self-contained simulation of a packet-filtering firewall with a
security log, suspicious-activity detection, alerts and a dashboard.
Only the Python standard library is used.

Run:   python firewall_monitor.py
"""

import csv
import ipaddress
import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from html import escape

INTERNAL_NET = ipaddress.ip_network("192.168.1.0/24")

# Well known ports -> traffic type
TRAFFIC_TYPES = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 25: "SMTP",
    23: "Telnet", 21: "FTP", 3389: "RDP", 445: "SMB", 3306: "MySQL",
}

# Detection thresholds (easy to tune)
SCAN_PORT_LIMIT = 6        # distinct ports from one source inside the window
FLOOD_PACKET_LIMIT = 20    # packets from one source inside the window
BLOCKED_LIMIT = 5          # repeated blocked attempts from one source
WINDOW_SECONDS = 10


# --------------------------------------------------------------------------
# 1. Data structures
# --------------------------------------------------------------------------
@dataclass
class Packet:
    time: int
    src: str
    dst: str
    port: int
    protocol: str

    @property
    def direction(self):
        return "Outgoing" if ipaddress.ip_address(self.src) in INTERNAL_NET else "Incoming"

    @property
    def traffic_type(self):
        return TRAFFIC_TYPES.get(self.port, "Other")


@dataclass
class Rule:
    id: int
    action: str
    src: str
    dst: str
    port: str
    protocol: str
    description: str

    def _ip_match(self, rule_value, ip):
        if rule_value == "any":
            return True
        return ipaddress.ip_address(ip) in ipaddress.ip_network(rule_value, strict=False)

    def matches(self, pkt):
        if not self._ip_match(self.src, pkt.src):
            return False
        if not self._ip_match(self.dst, pkt.dst):
            return False
        if self.port != "any" and int(self.port) != pkt.port:
            return False
        if self.protocol != "ANY" and self.protocol != pkt.protocol:
            return False
        return True


# --------------------------------------------------------------------------
# 2. Firewall engine  (first matching rule wins, default is DENY)
# --------------------------------------------------------------------------
class Firewall:
    def __init__(self, rule_file):
        with open(rule_file) as f:
            self.rules = [Rule(**r) for r in json.load(f)]

    def add_rule(self, rule):
        self.rules.append(rule)

    def remove_rule(self, rule_id):
        self.rules = [r for r in self.rules if r.id != rule_id]

    def decide(self, pkt):
        for rule in self.rules:
            if rule.matches(pkt):
                status = "Allowed" if rule.action == "ALLOW" else "Blocked"
                return status, f"Rule {rule.id}: {rule.description}"
        return "Blocked", "Default deny (no rule matched)"


# --------------------------------------------------------------------------
# 3. Suspicious activity detector
# --------------------------------------------------------------------------
class Detector:
    def __init__(self):
        self.history = defaultdict(list)     # src -> [(time, port, status)]
        self.raised = set()                   # avoid duplicate alerts
        self.alerts = []

    def _raise(self, time, src, kind, severity, detail):
        key = (src, kind)
        if key in self.raised:
            return
        self.raised.add(key)
        self.alerts.append({"time": time, "src": src, "type": kind,
                            "severity": severity, "detail": detail})

    def inspect(self, pkt, status):
        h = self.history[pkt.src]
        h.append((pkt.time, pkt.port, status))
        recent = [x for x in h if pkt.time - x[0] <= WINDOW_SECONDS]

        ports = {x[1] for x in recent}
        if len(ports) >= SCAN_PORT_LIMIT:
            self._raise(pkt.time, pkt.src, "Port Scan", "HIGH",
                        f"{len(ports)} different ports probed within {WINDOW_SECONDS}s")

        if len(recent) >= FLOOD_PACKET_LIMIT:
            self._raise(pkt.time, pkt.src, "DoS / Flood", "CRITICAL",
                        f"{len(recent)} packets within {WINDOW_SECONDS}s")

        blocked = [x for x in h if x[2] == "Blocked"]
        if len(blocked) >= BLOCKED_LIMIT:
            self._raise(pkt.time, pkt.src, "Repeated Blocked Access", "MEDIUM",
                        f"{len(blocked)} blocked attempts so far")

    def is_suspicious(self, src):
        return any(a["src"] == src for a in self.alerts)


# --------------------------------------------------------------------------
# 4. Traffic generator (simulated network)
# --------------------------------------------------------------------------
def generate_traffic(seed=17):
    random.seed(seed)
    pkts = []
    internal = [f"192.168.1.{n}" for n in (10, 15, 22, 40, 77)]
    servers = ["142.250.77.14", "151.101.1.69", "93.184.216.34", "8.8.8.8"]

    # normal everyday traffic
    for t in range(0, 60, 1):
        src = random.choice(internal)
        port, proto = random.choice([(443, "TCP"), (443, "TCP"), (80, "TCP"), (53, "UDP")])
        dst = "8.8.8.8" if port == 53 else random.choice(servers)
        pkts.append(Packet(t, src, dst, port, proto))

    # outsiders trying to reach the web server and SSH
    for t in (5, 14, 31, 48):
        pkts.append(Packet(t, "198.51.100.23", "192.168.1.10", 80, "TCP"))
    pkts.append(Packet(20, "198.51.100.23", "192.168.1.10", 22, "TCP"))

    # telnet and RDP attempts
    for t in (9, 11, 13):
        pkts.append(Packet(t, "45.33.32.156", "192.168.1.15", 23, "TCP"))
    for t in (25, 26):
        pkts.append(Packet(t, "185.220.101.5", "192.168.1.22", 3389, "TCP"))

    # port scan from one host (a new port every second)
    for i, port in enumerate([21, 22, 23, 25, 80, 110, 139, 445, 3306, 8080]):
        pkts.append(Packet(30 + i, "203.0.113.50", "192.168.1.10", port, "TCP"))

    # DoS style flood from a blacklisted host, 30 packets in 6 seconds
    for i in range(30):
        pkts.append(Packet(40 + i // 5, "203.0.113.66", "192.168.1.10", 80, "TCP"))

    pkts.sort(key=lambda p: p.time)
    return pkts


# --------------------------------------------------------------------------
# 5. Reporting helpers
# --------------------------------------------------------------------------
def write_log(rows, path):
    fields = ["No", "Time", "Source IP", "Destination IP", "Port", "Protocol",
              "Direction", "Traffic Type", "Access Status", "Reason", "Suspicious"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def write_alerts(alerts, path):
    with open(path, "w") as f:
        for a in alerts:
            f.write(f"[{a['severity']:<8}] t={a['time']:>2}s  {a['type']:<24} "
                    f"source {a['src']:<15} {a['detail']}\n")


def write_dashboard(rows, alerts, path):
    total = len(rows)
    allowed = sum(r["Access Status"] == "Allowed" for r in rows)
    blocked = total - allowed
    top_src = Counter(r["Source IP"] for r in rows if r["Access Status"] == "Blocked").most_common(5)
    by_type = Counter(r["Traffic Type"] for r in rows)

    def trs(items):
        return "".join(f"<tr><td>{escape(str(a))}</td><td>{escape(str(b))}</td></tr>" for a, b in items)

    alert_rows = "".join(
        f"<tr><td>{a['severity']}</td><td>{escape(a['type'])}</td><td>{a['src']}</td>"
        f"<td>{escape(a['detail'])}</td></tr>" for a in alerts)
    log_rows = "".join(
        f"<tr class='{r['Access Status'].lower()}'><td>{r['Time']}</td><td>{r['Source IP']}</td>"
        f"<td>{r['Destination IP']}</td><td>{r['Port']}/{r['Protocol']}</td><td>{r['Traffic Type']}</td>"
        f"<td>{r['Access Status']}</td></tr>" for r in rows[-25:])

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Network Traffic Dashboard</title>
<style>
body{{font-family:'Times New Roman',serif;margin:24px;color:#000}}
h1{{font-size:24px}} h2{{font-size:18px;margin-top:28px}}
.cards{{display:flex;gap:16px}} .card{{border:1px solid #000;padding:12px 20px;min-width:140px}}
.card b{{font-size:26px;display:block}}
table{{border-collapse:collapse;width:100%;margin-top:8px}}
td,th{{border:1px solid #000;padding:5px 8px;text-align:left;font-size:14px}}
th{{background:#e6e6e6}} tr.blocked td{{background:#f2f2f2}}
</style></head><body>
<h1>Network Traffic Dashboard</h1>
<div class="cards">
<div class="card">Total packets<b>{total}</b></div>
<div class="card">Allowed<b>{allowed}</b></div>
<div class="card">Blocked<b>{blocked}</b></div>
<div class="card">Security alerts<b>{len(alerts)}</b></div></div>
<h2>Security Alerts</h2><table><tr><th>Severity</th><th>Type</th><th>Source</th><th>Details</th></tr>{alert_rows}</table>
<h2>Top Blocked Sources</h2><table><tr><th>Source IP</th><th>Blocked packets</th></tr>{trs(top_src)}</table>
<h2>Traffic by Type</h2><table><tr><th>Type</th><th>Packets</th></tr>{trs(by_type.most_common())}</table>
<h2>Latest 25 Log Entries</h2><table><tr><th>Time</th><th>Source</th><th>Destination</th><th>Port/Proto</th><th>Type</th><th>Status</th></tr>{log_rows}</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# --------------------------------------------------------------------------
# 6. Main
# --------------------------------------------------------------------------
def main():
    fw = Firewall("rules.json")
    det = Detector()
    rows = []

    for no, pkt in enumerate(generate_traffic(), start=1):
        status, reason = fw.decide(pkt)
        det.inspect(pkt, status)
        rows.append({
            "No": no, "Time": pkt.time, "Source IP": pkt.src, "Destination IP": pkt.dst,
            "Port": pkt.port, "Protocol": pkt.protocol, "Direction": pkt.direction,
            "Traffic Type": pkt.traffic_type, "Access Status": status, "Reason": reason,
            "Suspicious": "No",
        })

    for r in rows:                     # mark every packet from a flagged source
        if det.is_suspicious(r["Source IP"]):
            r["Suspicious"] = "Yes"

    write_log(rows, "sample_output/security_log.csv")
    write_alerts(det.alerts, "sample_output/security_alerts.txt")
    write_dashboard(rows, det.alerts, "sample_output/dashboard.html")

    total = len(rows)
    allowed = sum(r["Access Status"] == "Allowed" for r in rows)
    print("=" * 60)
    print(" NETWORK TRAFFIC DASHBOARD (console view)")
    print("=" * 60)
    print(f" Total packets : {total}")
    print(f" Allowed       : {allowed}")
    print(f" Blocked       : {total - allowed}")
    print(f" Alerts raised : {len(det.alerts)}")
    print("-" * 60)
    for a in det.alerts:
        print(f" [{a['severity']}] {a['type']} from {a['src']} - {a['detail']}")
    print("-" * 60)
    print(" Traffic by type:", dict(Counter(r["Traffic Type"] for r in rows)))
    print(" Files written to the sample_output folder.")


if __name__ == "__main__":
    main()
