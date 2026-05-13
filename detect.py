"""
detect.py
Core detection engine — reads logs, applies rules, outputs alerts.
Each rule maps to a MITRE ATT&CK technique.
"""

import pandas as pd
import json
from datetime import datetime

# ── CONFIG ────────────────────────────────────────────────────────────────────
WINDOWS_LOG   = "windows_events.csv"
NETWORK_LOG   = "network_logs.csv"
ALERTS_OUTPUT = "alerts.json"

# Whitelisted service accounts — won't trigger brute force alerts
SERVICE_ACCOUNTS = ["svc_backup", "svc_monitor", "svc_deploy"]

# Exfiltration threshold: bytes in a single connection
EXFIL_THRESHOLD = 100000   # 100 KB

# Brute force: N failed logins within T seconds from same IP
BRUTE_FORCE_COUNT   = 5
BRUTE_FORCE_WINDOW  = 60   # seconds

# Port scan: N distinct ports hit from same IP within T seconds
PORT_SCAN_COUNT     = 8
PORT_SCAN_WINDOW    = 120  # seconds

# Off-hours window (24hr)
OFF_HOUR_START = 22   # 10 PM
OFF_HOUR_END   = 6    # 6 AM

alerts = []

def add_alert(severity, technique_id, technique_name, title, description, source_ip, user="-"):
    alerts.append({
        "id":             len(alerts) + 1,
        "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity":       severity,
        "mitre_id":       technique_id,
        "mitre_name":     technique_name,
        "title":          title,
        "description":    description,
        "source_ip":      source_ip,
        "user":           user,
    })
    sev_color = {"Critical":"🔴", "High":"🟠", "Medium":"🟡", "Low":"🔵"}
    print(f"  {sev_color.get(severity,'⚪')} [{severity}] {title} | IP: {source_ip} | User: {user}")

# ── RULE 1: Brute Force Detection ─────────────────────────────────────────────
def rule_brute_force(df):
    print("\n[*] Running Rule 1: Brute Force Detection (T1110)")
    failed = df[(df["event_id"] == "4625") & (~df["user"].isin(SERVICE_ACCOUNTS))].copy()
    failed["timestamp"] = pd.to_datetime(failed["timestamp"])
    failed = failed.sort_values("timestamp")

    flagged_ips = set()
    for ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        for i in range(len(times)):
            window = [t for t in times[i:] if (t - times[i]).total_seconds() <= BRUTE_FORCE_WINDOW]
            if len(window) >= BRUTE_FORCE_COUNT and ip not in flagged_ips:
                user = group.iloc[i]["user"]
                add_alert(
                    severity      = "High",
                    technique_id  = "T1110",
                    technique_name= "Brute Force",
                    title         = f"Brute force detected from {ip}",
                    description   = f"{len(window)} failed logins in {BRUTE_FORCE_WINDOW}s targeting user '{user}'",
                    source_ip     = ip,
                    user          = user,
                )
                flagged_ips.add(ip)

# ── RULE 2: Privilege Escalation ──────────────────────────────────────────────
def rule_privilege_escalation(df):
    print("\n[*] Running Rule 2: Privilege Escalation (T1068)")
    priv_events = df[df["event_id"] == "4672"]
    for _, row in priv_events.iterrows():
        if row["user"] not in SERVICE_ACCOUNTS:
            add_alert(
                severity      = "Critical",
                technique_id  = "T1068",
                technique_name= "Privilege Escalation",
                title         = f"Special privileges assigned to {row['user']}",
                description   = f"Event ID 4672: Admin-level privileges assigned at logon from {row['source_ip']}",
                source_ip     = row["source_ip"],
                user          = row["user"],
            )

# ── RULE 3: Persistence via Scheduled Task ────────────────────────────────────
def rule_scheduled_task(df):
    print("\n[*] Running Rule 3: Scheduled Task Persistence (T1053)")
    task_events = df[df["event_id"] == "4698"]
    for _, row in task_events.iterrows():
        if row["user"] not in SERVICE_ACCOUNTS:
            add_alert(
                severity      = "High",
                technique_id  = "T1053",
                technique_name= "Scheduled Task / Job",
                title         = f"Scheduled task created by {row['user']}",
                description   = f"Event ID 4698: Potential persistence mechanism — scheduled task created from {row['source_ip']}",
                source_ip     = row["source_ip"],
                user          = row["user"],
            )

# ── RULE 4: Off-Hours Login ────────────────────────────────────────────────────
def rule_off_hours(df):
    print("\n[*] Running Rule 4: Off-Hours Login (T1078)")
    logins = df[df["event_id"] == "4624"].copy()
    logins["timestamp"] = pd.to_datetime(logins["timestamp"])
    logins["hour"] = logins["timestamp"].dt.hour

    off = logins[(logins["hour"] >= OFF_HOUR_START) | (logins["hour"] < OFF_HOUR_END)]
    off = off[~off["user"].isin(SERVICE_ACCOUNTS)]

    for _, row in off.iterrows():
        add_alert(
            severity      = "Medium",
            technique_id  = "T1078",
            technique_name= "Valid Accounts",
            title         = f"Off-hours login by {row['user']}",
            description   = f"Successful login at {row['timestamp'].strftime('%H:%M')} (outside business hours) from {row['source_ip']}",
            source_ip     = row["source_ip"],
            user          = row["user"],
        )

# ── RULE 5: Port Scan Detection ───────────────────────────────────────────────
def rule_port_scan(net_df):
    print("\n[*] Running Rule 5: Port Scan Detection (T1046)")
    net_df = net_df.copy()
    net_df["timestamp"] = pd.to_datetime(net_df["timestamp"])
    net_df = net_df.sort_values("timestamp")

    flagged = set()
    for src_ip, group in net_df.groupby("src_ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        for i in range(len(times)):
            window_rows = group[
                (group["timestamp"] >= times[i]) &
                (group["timestamp"] <= times[i] + pd.Timedelta(seconds=PORT_SCAN_WINDOW))
            ]
            distinct_ports = window_rows["dst_port"].nunique()
            if distinct_ports >= PORT_SCAN_COUNT and src_ip not in flagged:
                add_alert(
                    severity      = "High",
                    technique_id  = "T1046",
                    technique_name= "Network Service Discovery",
                    title         = f"Port scan detected from {src_ip}",
                    description   = f"{distinct_ports} distinct ports probed within {PORT_SCAN_WINDOW}s — possible reconnaissance",
                    source_ip     = src_ip,
                )
                flagged.add(src_ip)

# ── RULE 6: Data Exfiltration ─────────────────────────────────────────────────
def rule_exfiltration(net_df):
    print("\n[*] Running Rule 6: Data Exfiltration (T1041)")
    large = net_df[net_df["bytes_sent"] > EXFIL_THRESHOLD]
    flagged = set()
    for _, row in large.iterrows():
        key = (row["src_ip"], row["dst_ip"])
        if key not in flagged:
            mb = round(row["bytes_sent"] / 1_000_000, 2)
            add_alert(
                severity      = "Critical",
                technique_id  = "T1041",
                technique_name= "Exfiltration Over C2 Channel",
                title         = f"Large data transfer from {row['src_ip']}",
                description   = f"{mb} MB sent to external IP {row['dst_ip']} on port {row['dst_port']}",
                source_ip     = row["src_ip"],
            )
            flagged.add(key)

# ── RULE 7: Suspicious Telnet / FTP (Legacy Protocol) ────────────────────────
def rule_legacy_protocols(net_df):
    print("\n[*] Running Rule 7: Legacy Protocol Usage (T1021)")
    legacy = net_df[net_df["dst_port"].isin([21, 23])]
    for _, row in legacy.iterrows():
        proto = "FTP" if row["dst_port"] == 21 else "Telnet"
        add_alert(
            severity      = "Medium",
            technique_id  = "T1021",
            technique_name= "Remote Services",
            title         = f"Insecure {proto} connection from {row['src_ip']}",
            description   = f"Plaintext protocol {proto} (port {row['dst_port']}) used — credentials at risk",
            source_ip     = row["src_ip"],
        )

# ── RULE 8: Repeated DENY from same IP ────────────────────────────────────────
def rule_repeated_deny(net_df):
    print("\n[*] Running Rule 8: Repeated Firewall Denials (T1110.003)")
    denied = net_df[net_df["action"] == "DENY"]
    counts = denied.groupby("src_ip").size()
    for ip, count in counts.items():
        if count >= 5:
            add_alert(
                severity      = "Low",
                technique_id  = "T1110.003",
                technique_name= "Password Spraying",
                title         = f"Repeated firewall denials from {ip}",
                description   = f"{count} denied connections — possible blocked attack or misconfiguration",
                source_ip     = ip,
            )

# ── MAIN ──────────────────────────────────────────────────────────────────────
def run_detection():
    print("=" * 60)
    print("  SOC THREAT DETECTION ENGINE")
    print("=" * 60)

    # Load logs
    try:
        win_df = pd.read_csv(WINDOWS_LOG)
        win_df["event_id"] = win_df["event_id"].astype(str)
        print(f"\n[+] Loaded {len(win_df)} Windows events from {WINDOWS_LOG}")
    except FileNotFoundError:
        print(f"[!] {WINDOWS_LOG} not found. Run generate_logs.py first.")
        return

    try:
        net_df = pd.read_csv(NETWORK_LOG)
        print(f"[+] Loaded {len(net_df)} network events from {NETWORK_LOG}")
    except FileNotFoundError:
        print(f"[!] {NETWORK_LOG} not found. Run generate_logs.py first.")
        return

    print("\n[*] Running detection rules...")

    # Windows rules
    rule_brute_force(win_df)
    rule_privilege_escalation(win_df)
    rule_scheduled_task(win_df)
    rule_off_hours(win_df)

    # Network rules
    rule_port_scan(net_df)
    rule_exfiltration(net_df)
    rule_legacy_protocols(net_df)
    rule_repeated_deny(net_df)

    # Save alerts
    with open(ALERTS_OUTPUT, "w") as f:
        json.dump(alerts, f, indent=2)

    # Summary
    print("\n" + "=" * 60)
    print(f"  DETECTION COMPLETE — {len(alerts)} alerts generated")
    print("=" * 60)

    severity_counts = {}
    for a in alerts:
        severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1

    for sev in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts.get(sev, 0)
        bar = "█" * count
        print(f"  {sev:<10} {bar} ({count})")

    print(f"\n[✓] Alerts saved to {ALERTS_OUTPUT}")
    print("[→] Run: python app.py — then open http://localhost:5000\n")

if __name__ == "__main__":
    run_detection()
