"""
generate_logs.py
Generates realistic Windows Event Logs and network logs for the SOC dashboard.
Run this first to create sample data.
"""

import csv
import random
from datetime import datetime, timedelta

# ── CONFIG ────────────────────────────────────────────────────────────────────
TOTAL_EVENTS   = 500
OUTPUT_WINDOWS = "windows_events.csv"
OUTPUT_NETWORK = "network_logs.csv"

# Known good service accounts (whitelisted)
SERVICE_ACCOUNTS = ["svc_backup", "svc_monitor", "svc_deploy"]

# Attacker IPs (simulated bad actors)
ATTACKER_IPS = ["192.168.1.200", "10.0.0.99", "172.16.0.50"]

# Normal user pool
USERS = ["alice", "bob", "charlie", "diana", "eve", "frank"] + SERVICE_ACCOUNTS

# Internal IPs
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(2, 20)]

# Common ports
PORTS = [22, 80, 443, 3389, 8080, 21, 23, 445, 1433]

def random_time(start, end):
    delta = end - start
    return start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))

def generate_windows_events():
    """Generate Windows Security Event Log entries."""
    events = []
    base_time = datetime.now() - timedelta(hours=24)
    end_time  = datetime.now()

    # ── Normal logins ─────────────────────────────────────────────────────────
    for _ in range(200):
        events.append({
            "timestamp":  random_time(base_time, end_time).strftime("%Y-%m-%d %H:%M:%S"),
            "event_id":   "4624",
            "description":"Successful logon",
            "user":       random.choice(USERS),
            "source_ip":  random.choice(INTERNAL_IPS),
            "status":     "Success",
        })

    # ── Failed logins (normal - occasional mistakes) ──────────────────────────
    for _ in range(50):
        events.append({
            "timestamp":  random_time(base_time, end_time).strftime("%Y-%m-%d %H:%M:%S"),
            "event_id":   "4625",
            "description":"Failed logon",
            "user":       random.choice(USERS),
            "source_ip":  random.choice(INTERNAL_IPS),
            "status":     "Failure",
        })

    # ── ATTACK: Brute force — rapid failed logins from attacker IP ────────────
    brute_start = base_time + timedelta(hours=6)
    for i in range(12):
        events.append({
            "timestamp":  (brute_start + timedelta(seconds=i*4)).strftime("%Y-%m-%d %H:%M:%S"),
            "event_id":   "4625",
            "description":"Failed logon",
            "user":       "administrator",
            "source_ip":  ATTACKER_IPS[0],
            "status":     "Failure",
        })

    # ── ATTACK: Privilege escalation ──────────────────────────────────────────
    priv_time = base_time + timedelta(hours=8)
    events.append({
        "timestamp":  priv_time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_id":   "4672",
        "description":"Special privileges assigned to new logon",
        "user":       "eve",
        "source_ip":  ATTACKER_IPS[1],
        "status":     "Success",
    })

    # ── ATTACK: Scheduled task created (persistence) ──────────────────────────
    task_time = base_time + timedelta(hours=9)
    events.append({
        "timestamp":  task_time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_id":   "4698",
        "description":"A scheduled task was created",
        "user":       "eve",
        "source_ip":  ATTACKER_IPS[1],
        "status":     "Success",
    })

    # ── Off-hours logins (2 AM - 4 AM) ───────────────────────────────────────
    off_base = base_time.replace(hour=2, minute=0, second=0)
    for _ in range(5):
        events.append({
            "timestamp":  (off_base + timedelta(minutes=random.randint(0,120))).strftime("%Y-%m-%d %H:%M:%S"),
            "event_id":   "4624",
            "description":"Successful logon",
            "user":       random.choice(["alice", "bob"]),
            "source_ip":  random.choice(INTERNAL_IPS),
            "status":     "Success",
        })

    random.shuffle(events)
    with open(OUTPUT_WINDOWS, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp","event_id","description","user","source_ip","status"])
        writer.writeheader()
        writer.writerows(events)
    print(f"[+] Generated {len(events)} Windows events → {OUTPUT_WINDOWS}")

def generate_network_logs():
    """Generate network traffic log entries."""
    events = []
    base_time = datetime.now() - timedelta(hours=24)
    end_time  = datetime.now()

    # ── Normal traffic ────────────────────────────────────────────────────────
    for _ in range(200):
        events.append({
            "timestamp":  random_time(base_time, end_time).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":     random.choice(INTERNAL_IPS),
            "dst_ip":     f"8.8.{random.randint(1,254)}.{random.randint(1,254)}",
            "src_port":   random.randint(1024, 65535),
            "dst_port":   random.choice([80, 443]),
            "protocol":   "TCP",
            "bytes_sent": random.randint(200, 5000),
            "action":     "ALLOW",
        })

    # ── ATTACK: Port scan from attacker IP ────────────────────────────────────
    scan_start = base_time + timedelta(hours=3)
    target_ip  = random.choice(INTERNAL_IPS)
    for port in [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080, 8443]:
        events.append({
            "timestamp":  (scan_start + timedelta(seconds=port//10)).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":     ATTACKER_IPS[0],
            "dst_ip":     target_ip,
            "src_port":   random.randint(1024, 65535),
            "dst_port":   port,
            "protocol":   "TCP",
            "bytes_sent": 60,
            "action":     "DENY",
        })

    # ── ATTACK: Data exfiltration (large outbound transfer) ───────────────────
    exfil_time = base_time + timedelta(hours=10)
    for _ in range(8):
        events.append({
            "timestamp":  (exfil_time + timedelta(minutes=random.randint(0,30))).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":     ATTACKER_IPS[1],
            "dst_ip":     f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "src_port":   random.randint(1024, 65535),
            "dst_port":   443,
            "protocol":   "TCP",
            "bytes_sent": random.randint(500000, 2000000),
            "action":     "ALLOW",
        })

    random.shuffle(events)
    with open(OUTPUT_NETWORK, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp","src_ip","dst_ip","src_port","dst_port","protocol","bytes_sent","action"])
        writer.writeheader()
        writer.writerows(events)
    print(f"[+] Generated {len(events)} network events → {OUTPUT_NETWORK}")

if __name__ == "__main__":
    generate_windows_events()
    generate_network_logs()
    print("\n[✓] Sample logs ready. Run: python detect.py")
