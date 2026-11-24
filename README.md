# 📡 NetWatch – Network Monitor & Exposure Auditor

**Cybersecurity Capstone Project (Module 06) · Codomax Digital Solutions**

NetWatch is a defensive network monitoring toolkit (Python standard library only + browser dashboard) with three modules:

| Module | Command | What it does |
|---|---|---|
| **Uptime & latency monitor** | `monitor` | TCP connect checks → status, avg/min/max latency, jitter, packet loss; alerts for HOST DOWN, PACKET LOSS, HIGH LATENCY, LATENCY SPIKE |
| **Port exposure audit** | `scan` | Finds open ports on hosts **you own**, rates risk (Telnet, Redis, RDP, DB ports…) and gives hardening advice |
| **Connection analyzer** | `connections` | Parses `ss`/`netstat` output → connection flood, SYN-flood suspects, risky listeners, backdoor/C2 ports |

The **dashboard** (`index.html`) visualises everything with sparklines, status pills, severity-ranked alerts and recommended actions. 100% client-side.

> ⚖️ **Ethics & scope:** use only on networks/hosts you own or have written permission to test. The scanner **refuses public IPs** unless
> `--i-have-written-permission` is passed. Demo data is synthetic (RFC 5737 / private ranges). No exploitation features.

## Quick start
```bash
git clone https://github.com/<your-username>/netwatch && cd netwatch
python netwatch.py monitor sample_data/targets.json -n 5 -o monitor.json
python netwatch.py scan 127.0.0.1 --ports 22,80,3306,6379 -o scan.json
python netwatch.py connections sample_data/connections.txt -o conns.json     # or no file → runs `ss -tunaH` (Linux)
python -m unittest tests/test_netwatch.py
```
Open `index.html` → **Choose Files** → select `monitor.json`, `scan.json`, `conns.json` together (they merge), or click **Load demo data**.

Edit `sample_data/targets.json` to monitor your own devices: `[{"name":"Router","host":"192.168.1.1","port":80}]`.
Schedule it: `*/5 * * * * python /path/netwatch.py monitor targets.json -n 3 -o /var/log/netwatch/$(date +\%F-\%H\%M).json`

## Structure
```
netwatch/  index.html · netwatch.py · sample_data/ · tests/ · docs/
```
Docs: `ARCHITECTURE.md`, `TESTING_REPORT.md`, `DEMO_SCRIPT.md`, `LINKEDIN_POST.md`, `DEPLOY_GUIDE.md`.

## Roadmap
ICMP/SNMP checks · email/Slack alerts · GeoIP · time-series history · Windows `netstat` parser.
## License
MIT
