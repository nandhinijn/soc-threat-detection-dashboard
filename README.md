# SOC Log Analysis & Threat Hunting Dashboard

A Python-based Security Operations Centre (SOC) tool that ingests Windows Event Logs and network traffic logs, applies MITRE ATT&CK-mapped detection rules, and visualises alerts through a Flask web dashboard.

Built as a portfolio project to demonstrate core SOC Analyst L1 skills: log analysis, threat detection, alert triage, and incident reporting.

---

## Features

- 8 detection rules mapped to MITRE ATT&CK techniques
- Parses Windows Security Event Logs and network traffic logs
- Severity classification: Critical / High / Medium / Low
- Flask web dashboard with charts and alert triage table
- REST API endpoints for alert data
- False-positive reduction via service account whitelisting

---

## Detection Rules

| Rule | MITRE ID | Technique | Severity |
|------|----------|-----------|----------|
| Brute Force | T1110 | Credential Access | High |
| Privilege Escalation | T1068 | Privilege Escalation | Critical |
| Scheduled Task Persistence | T1053 | Persistence | High |
| Off-Hours Login | T1078 | Valid Accounts | Medium |
| Port Scan | T1046 | Network Service Discovery | High |
| Data Exfiltration | T1041 | Exfiltration | Critical |
| Legacy Protocol (FTP/Telnet) | T1021 | Remote Services | Medium |
| Repeated Firewall Denials | T1110.003 | Password Spraying | Low |

---

## Project Structure

```
soc_dashboard/
├── generate_logs.py   # Generates realistic sample log data
├── detect.py          # Detection engine — runs all rules
├── app.py             # Flask dashboard
├── windows_events.csv # Generated Windows Event Log (auto-created)
├── network_logs.csv   # Generated network log (auto-created)
├── alerts.json        # Detection output (auto-created)
└── README.md
```

---

## Setup & Run

### Requirements
```
Python 3.8+
pip install flask pandas matplotlib
```

### Steps

**1. Generate sample logs**
```bash
python generate_logs.py
```

**2. Run detection engine**
```bash
python detect.py
```

**3. Start the dashboard**
```bash
python app.py
```

**4. Open in browser**
```
http://localhost:5000
```

---

## Sample Output

```
======================================================
  SOC THREAT DETECTION ENGINE
======================================================

[*] Running Rule 1: Brute Force Detection (T1110)
  🟠 [High] Brute force detected from 192.168.1.200 | User: administrator

[*] Running Rule 2: Privilege Escalation (T1068)
  🔴 [Critical] Special privileges assigned to eve | IP: 10.0.0.99

[*] Running Rule 3: Scheduled Task Persistence (T1053)
  🟠 [High] Scheduled task created by eve | IP: 10.0.0.99

======================================================
  DETECTION COMPLETE — 14 alerts generated
======================================================
  Critical   ██ (2)
  High       ████ (4)
  Medium     ██████ (6)
  Low        ██ (2)
```

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Web dashboard |
| `GET /api/alerts` | All alerts as JSON |
| `GET /api/stats` | Summary statistics |

---

## Skills Demonstrated

- Log parsing and analysis (Windows Event IDs, network logs)
- Detection rule engineering mapped to MITRE ATT&CK
- Alert triage with severity classification
- False positive reduction (service account whitelisting)
- Python scripting with pandas for data processing
- Flask web application development
- REST API design
- Security documentation and reporting

---

## What I Learned

- How SIEM tools like Splunk work under the hood — ingestion → parsing → correlation → alerting
- Why false positive tuning is one of the most important and time-consuming parts of SOC work
- How MITRE ATT&CK provides a common language for mapping detections to real attacker behaviour
- The difference between detection (finding the event) and triage (deciding what to do about it)

---

## Future Improvements

- Real-time log streaming using Kafka
- AbuseIPDB threat intelligence feed integration for IP enrichment
- Automated response actions (SOAR-style) — e.g. auto-block IP after 10 failed logins
- Docker containerisation for easy deployment
- Elastic Stack (ELK) integration for production-grade log management

---

