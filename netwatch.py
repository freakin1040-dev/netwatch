#!/usr/bin/env python3
"""NetWatch - defensive network monitor (stdlib only).
  monitor      TCP uptime/latency/loss checks with anomaly alerts
  scan         port audit of hosts YOU OWN (private/loopback only by default)
  connections  analyze `ss`/`netstat` output for suspicious connections
Use only on networks and hosts you own or are explicitly authorized to test."""
import argparse, ipaddress, json, socket, statistics, subprocess, sys, time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

RISKY = {21: ("FTP", "High", "Cleartext credentials; use SFTP"), 23: ("Telnet", "Critical", "Cleartext remote shell; disable"),
         25: ("SMTP", "Low", "Ensure not an open relay"), 69: ("TFTP", "High", "No authentication"),
         135: ("MSRPC", "High", "Block from untrusted networks"), 139: ("NetBIOS", "High", "Disable if unused"),
         445: ("SMB", "High", "Patch; restrict to LAN"), 1433: ("MSSQL", "High", "Do not expose DB to network"),
         3306: ("MySQL", "High", "Bind to localhost / firewall"), 3389: ("RDP", "High", "Use VPN + MFA"),
         5432: ("PostgreSQL", "High", "Bind to localhost / firewall"), 5900: ("VNC", "High", "Use tunnel/VPN"),
         6379: ("Redis", "Critical", "Require auth; never expose"), 27017: ("MongoDB", "High", "Require auth; firewall"),
         22: ("SSH", "Low", "Keys only, disable root login"), 80: ("HTTP", "Low", "Redirect to HTTPS"),
         443: ("HTTPS", "Info", "Keep TLS config current"), 53: ("DNS", "Low", "Restrict recursion"),
         8080: ("HTTP-alt", "Low", "Review exposure")}
DEFAULT_PORTS = sorted(RISKY)

def tcp_check(host, port, timeout=2.0):
    """Return connect latency in ms, or None on failure."""
    t = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout): pass
        return round((time.perf_counter() - t) * 1000, 2)
    except OSError:
        return None

def evaluate(name, host, port, samples, latency_ms=150):
    """Turn raw samples (ms or None) into stats + alerts."""
    ok = [s for s in samples if s is not None]
    loss = round(100 * (len(samples) - len(ok)) / len(samples), 1) if samples else 0
    alerts = []
    if not ok: alerts.append({"severity": "Critical", "type": "HOST DOWN", "target": name, "detail": f"{host}:{port} unreachable (100% loss)"})
    else:
        avg = statistics.mean(ok)
        if loss >= 20: alerts.append({"severity": "High", "type": "PACKET LOSS", "target": name, "detail": f"{loss}% failed checks"})
        if avg > latency_ms: alerts.append({"severity": "Medium", "type": "HIGH LATENCY", "target": name, "detail": f"avg {avg:.1f} ms > {latency_ms} ms"})
        if len(ok) >= 4:
            base = statistics.median(ok); spikes = [s for s in ok if s > max(base * 3, base + 50)]
            if spikes: alerts.append({"severity": "Medium", "type": "LATENCY SPIKE", "target": name, "detail": f"{len(spikes)} sample(s) up to {max(spikes)} ms vs median {base} ms"})
    st = {"name": name, "host": host, "port": port, "sent": len(samples), "ok": len(ok), "loss_pct": loss,
          "avg_ms": round(statistics.mean(ok), 2) if ok else None, "min_ms": min(ok) if ok else None,
          "max_ms": max(ok) if ok else None, "jitter_ms": round(statistics.pstdev(ok), 2) if len(ok) > 1 else 0,
          "status": "DOWN" if not ok else ("DEGRADED" if alerts else "UP"), "samples": samples}
    return st, alerts

def monitor(targets, rounds=5, interval=1.0, latency_ms=150):
    data = {n: [] for n in (t["name"] for t in targets)}
    for r in range(rounds):
        for t in targets: data[t["name"]].append(tcp_check(t["host"], t["port"]))
        if r < rounds - 1: time.sleep(interval)
    stats, alerts = [], []
    for t in targets:
        s, a = evaluate(t["name"], t["host"], t["port"], data[t["name"]], latency_ms); stats.append(s); alerts += a
    return {"monitor": {"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "targets": stats}, "alerts": alerts}

def scope_ok(host, authorized):
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    return ip.is_private or ip.is_loopback or authorized

def scan(host, ports=None, timeout=0.6, authorized=False):
    if not scope_ok(host, authorized):
        raise PermissionError("Refusing to scan a public address. Re-run with --i-have-written-permission only if authorized.")
    ports = ports or DEFAULT_PORTS
    with ThreadPoolExecutor(32) as ex: res = list(ex.map(lambda p: (p, tcp_check(host, p, timeout)), ports))
    openp, alerts = [], []
    for p, lat in res:
        if lat is None: continue
        svc, sev, tip = RISKY.get(p, ("unknown", "Medium", "Unrecognized service; verify it is intended"))
        openp.append({"port": p, "service": svc, "risk": sev, "advice": tip})
        if sev in ("Critical", "High"): alerts.append({"severity": sev, "type": "RISKY OPEN PORT", "target": host, "detail": f"{p}/{svc}: {tip}"})
    return {"scan": {"host": host, "ports_checked": len(ports), "open": openp}, "alerts": alerts}

def split_addr(a):
    h, _, p = a.rpartition(":"); return h.strip("[]"), (int(p) if p.isdigit() else 0)

def parse_ss(text):
    rows = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 6 or f[0] not in ("tcp", "udp"): continue
        (lh, lp), (rh, rp) = split_addr(f[4]), split_addr(f[5])
        rows.append({"proto": f[0], "state": f[1], "local_ip": lh, "local_port": lp, "remote_ip": rh, "remote_port": rp})
    return rows

def analyze_connections(rows, conn_threshold=10, syn_threshold=5):
    alerts, est = [], [r for r in rows if r["state"] in ("ESTAB", "ESTABLISHED")]
    per_ip = Counter(r["remote_ip"] for r in est)
    for ip, n in per_ip.items():
        if n >= conn_threshold: alerts.append({"severity": "High", "type": "CONNECTION FLOOD", "target": ip, "detail": f"{n} established connections from one remote IP"})
    syn = Counter(r["remote_ip"] for r in rows if r["state"] in ("SYN-RECV", "SYN_RECV"))
    for ip, n in syn.items():
        if n >= syn_threshold: alerts.append({"severity": "High", "type": "SYN FLOOD SUSPECT", "target": ip, "detail": f"{n} half-open connections"})
    for r in rows:
        if r["state"] == "LISTEN" and r["local_port"] in RISKY and RISKY[r["local_port"]][1] in ("Critical", "High") and r["local_ip"] in ("0.0.0.0", "*", "::", ""):
            alerts.append({"severity": RISKY[r["local_port"]][1], "type": "RISKY LISTENER", "target": f"port {r['local_port']}", "detail": f"{RISKY[r['local_port']][0]} listening on all interfaces"})
    for r in est:
        if r["remote_port"] in (4444, 6667, 31337, 1337): alerts.append({"severity": "High", "type": "SUSPICIOUS REMOTE PORT", "target": r["remote_ip"], "detail": f"outbound to port {r['remote_port']} (common backdoor/C2 port)"})
    seen = set(); alerts = [a for a in alerts if (a["type"], a["target"]) not in seen and not seen.add((a["type"], a["target"]))]
    return {"connections": {"total": len(rows), "established": len(est), "listening": sum(r["state"] == "LISTEN" for r in rows),
            "top_remotes": per_ip.most_common(5)}, "alerts": alerts}

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    m = sp.add_parser("monitor"); m.add_argument("targets", help="JSON file: [{name,host,port}]"); m.add_argument("-n", "--rounds", type=int, default=5); m.add_argument("-i", "--interval", type=float, default=1); m.add_argument("--latency", type=float, default=150)
    s = sp.add_parser("scan"); s.add_argument("host"); s.add_argument("--ports", help="comma list"); s.add_argument("--i-have-written-permission", action="store_true")
    c = sp.add_parser("connections"); c.add_argument("file", nargs="?", help="ss/netstat output file (default: run `ss -tunaH`)")
    for p in (m, s, c): p.add_argument("-o", "--output")
    a = ap.parse_args()
    if a.cmd == "monitor": r = monitor(json.load(open(a.targets)), a.rounds, a.interval, a.latency)
    elif a.cmd == "scan":
        try: r = scan(a.host, [int(x) for x in a.ports.split(",")] if a.ports else None, authorized=a.i_have_written_permission)
        except PermissionError as e: sys.exit(str(e))
    else: r = analyze_connections(parse_ss(open(a.file).read() if a.file else subprocess.run(["ss", "-tunaH"], capture_output=True, text=True).stdout))
    for al in r["alerts"]: print(f"[{al['severity'].upper():8}] {al['type']:22} {al['target']} - {al['detail']}")
    print(f"{len(r['alerts'])} alert(s)")
    if a.output: json.dump(r, open(a.output, "w"), indent=2); print("saved", a.output)

if __name__ == "__main__": main()
