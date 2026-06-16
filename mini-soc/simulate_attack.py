"""
simulate_attack.py — Injecte des logs d'attaque réalistes dans Elasticsearch
Simule : Hydra brute-force SSH + Nmap scan + Nikto web scan + accès DVWA
"""
from elasticsearch import Elasticsearch
from datetime import datetime, timezone, timedelta
import random
import time

es = Elasticsearch("http://localhost:9200", basic_auth=("elastic", "changeme"))

ATTACKER_IP  = "192.168.50.30"   # VM1
VICTIM_IP    = "192.168.50.20"     # VM2
TODAY        = datetime.now(timezone.utc)
INDEX        = f"soc-logs-{TODAY.strftime('%Y.%m.%d')}"

def ts(delta_minutes=0):
    return (TODAY + timedelta(minutes=delta_minutes)).isoformat()

def inject(docs, label):
    for doc in docs:
        es.index(index=INDEX, document=doc)
    print(f"  [{label}] {len(docs)} logs injectés → {INDEX}")

# ── 1. Hydra SSH Brute Force (200 tentatives) ────────────────────────────────
ssh_users = ["root", "admin", "ubuntu", "user", "pi", "test", "oracle"]
ssh_failed_logs = []
for i in range(200):
    user = random.choice(ssh_users)
    port = random.randint(40000, 65000)
    t = ts(delta_minutes=-(200 - i) * 0.1)  # étalé sur ~20 min
    ssh_failed_logs.append({
        "@timestamp": t,
        "log_type": "auth",
        "message": f"Failed password for {user} from {ATTACKER_IP} port {port} ssh2",
        "log_message": f"Failed password for {user} from {ATTACKER_IP} port {port} ssh2",
        "ssh_user": user,
        "src_ip": ATTACKER_IP,
        "src_port": str(port),
        "hostname": "victim-VMware-Virtual-Platform",
        "severity": "high",
        "tags": ["ssh_failed", "beats_input_codec_plain_applied"],
        "host": {"name": "victim-VMware-Virtual-Platform"},
        "agent": {"type": "filebeat", "version": "8.19.13"}
    })
inject(ssh_failed_logs, "Hydra SSH BruteForce")

# ── 2. 3 Connexions SSH réussies (après brute force) ────────────────────────
ssh_success_logs = []
for i in range(3):
    t = ts(delta_minutes=-i*2)
    ssh_success_logs.append({
        "@timestamp": t,
        "log_type": "auth",
        "message": f"Accepted password for root from {ATTACKER_IP} port 51234 ssh2",
        "log_message": f"Accepted password for root from {ATTACKER_IP} port 51234 ssh2",
        "ssh_user": "root",
        "src_ip": ATTACKER_IP,
        "hostname": "victim-VMware-Virtual-Platform",
        "severity": "info",
        "tags": ["ssh_success", "beats_input_codec_plain_applied"],
        "host": {"name": "victim-VMware-Virtual-Platform"},
        "agent": {"type": "filebeat", "version": "8.19.13"}
    })
inject(ssh_success_logs, "SSH Login Success")

# ── 3. Nmap scan → Suricata IDS alerts ──────────────────────────────────────
suricata_logs = []
signatures = [
    "ET SCAN Nmap Scripting Engine User-Agent Detected",
    "ET SCAN Potential SSH Scan",
    "ET SCAN Potential VNC Scan",
    "ET SCAN NMAP -sS window 1024",
    "GPL SCAN nmap XMAS"
]
for i, sig in enumerate(signatures):
    suricata_logs.append({
        "@timestamp": ts(delta_minutes=-(10 - i)),
        "log_type": "suricata",
        "event_type": "alert",
        "src_ip": ATTACKER_IP,
        "dest_ip": VICTIM_IP,
        "alert": {"signature": sig, "category": "Attempted Information Leak", "severity": 2},
        "hostname": "victim-VMware-Virtual-Platform",
        "severity": "critical",
        "tags": ["ids_alert", "beats_input_codec_plain_applied"],
        "host": {"name": "victim-VMware-Virtual-Platform"},
        "agent": {"type": "filebeat", "version": "8.19.13"}
    })
inject(suricata_logs, "Nmap/Suricata IDS")

# ── 4. Nikto web scan → Apache 400/404 errors ───────────────────────────────
nikto_paths = [
    "/admin", "/phpmyadmin", "/.env", "/wp-login.php", "/shell.php",
    "/etc/passwd", "/config.php", "/../../../etc/shadow",
    "/dvwa/vulnerabilities/sqli/", "/dvwa/vulnerabilities/xss_r/"
]
apache_logs = []
for i, path in enumerate(nikto_paths * 5):
    code = random.choice([400, 401, 403, 404, 500])
    apache_logs.append({
        "@timestamp": ts(delta_minutes=-(50 - i * 0.2)),
        "log_type": "apache_access",
        "src_ip": ATTACKER_IP,
        "clientip": ATTACKER_IP,
        "request": f"GET {path} HTTP/1.1",
        "verb": "GET",
        "rawrequest": path,
        "response": code,
        "bytes": random.randint(200, 4000),
        "http_user_agent": "Mozilla/5.00 (Nikto/2.1.6)",
        "hostname": "victim-VMware-Virtual-Platform",
        "severity": "high" if code >= 500 else "medium",
        "tags": ["http_error", "beats_input_codec_plain_applied"],
        "host": {"name": "victim-VMware-Virtual-Platform"}
    })
inject(apache_logs, "Nikto Web Scan")

# ── 5. SQLMap → injection SQL dans DVWA ─────────────────────────────────────
sqli_payloads = [
    "/?id=1' OR '1'='1", "/?id=1 UNION SELECT 1,2,3--",
    "/?id=1; DROP TABLE users--", "/?id=1' AND SLEEP(5)--"
]
sqli_logs = []
for i, payload in enumerate(sqli_payloads * 3):
    sqli_logs.append({
        "@timestamp": ts(delta_minutes=-(5 - i * 0.3)),
        "log_type": "apache_access",
        "src_ip": ATTACKER_IP,
        "clientip": ATTACKER_IP,
        "request": f"GET /dvwa/vulnerabilities/sqli/{payload} HTTP/1.1",
        "verb": "GET",
        "response": random.choice([200, 500]),
        "bytes": random.randint(500, 8000),
        "http_user_agent": "sqlmap/1.7.8",
        "hostname": "victim-VMware-Virtual-Platform",
        "severity": "critical",
        "tags": ["http_error", "sql_injection", "beats_input_codec_plain_applied"],
        "host": {"name": "victim-VMware-Virtual-Platform"}
    })
inject(sqli_logs, "SQLMap Injection")

# ── Résumé ───────────────────────────────────────────────────────────────────
time.sleep(1)
count = es.count(index=INDEX)["count"]
print(f"\n=== Simulation terminée ===")
print(f"Index : {INDEX}")
print(f"Total logs dans cet index : {count}")
print(f"\nAttendez 60s puis vérifiez :")
print(f"  Incidents : http://192.168.50.10:5000/incidents")
print(f"  Kibana    : http://192.168.50.10:5601/app/discover")
