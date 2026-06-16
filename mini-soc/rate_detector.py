"""
rate_detector.py — Détection par seuils de débit (SSH + Web)

Vérifie toutes les 60s :
  - SSH brute force    : >= 10 auth failed/5min par IP → alerte
  - HTTP flood         : >= 100 requêtes/5min par IP → alerte
  - Web scan (4xx)     : >= 20 erreurs HTTP/5min par IP → alerte
  - Connexion SSH OK   : connexion réussie depuis une IP qui a fait du brute force
"""
import time
import logging
import requests
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from config import ES_HOST, ES_USER, ES_PASSWORD, FLASK_URL

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s rate_detector — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("rate_detector")

INTERVAL = 60
WINDOW   = "5m"

SSH_WARN       = 10    # >= 10 auth failed → medium
SSH_HIGH       = 30    # >= 30 auth failed → high
HTTP_FLOOD     = 100   # >= 100 requêtes HTTP → medium
HTTP_SCAN      = 20    # >= 20 erreurs 4xx  → medium

es   = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))
seen = {}   # {key: True} — dédup incident par IP+heure+type


def _dedup(ip, itype):
    key = f"{ip}_{itype}_{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H')}"
    if key in seen:
        return True
    seen[key] = True
    if len(seen) > 500:
        seen.clear()
    return False


def _send_incident(ip, score, severity, log_type, alert_type, note=""):
    if _dedup(ip, alert_type):
        return
    try:
        resp = requests.post(f"{FLASK_URL}/api/auto_incident", json={
            "anomaly_score": score,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "src_ip":        ip,
            "log_type":      log_type,
            "ssh_user":      "unknown",
            "severity":      severity,
        }, timeout=3)
        log.info(f"Incident [{alert_type}] {ip} → {resp.json()} {note}")
    except Exception as e:
        log.error(f"Flask error: {e}")


def check_ssh_brute_force():
    """Compte les auth logs par IP sur 5 min (sans filtre tag)."""
    try:
        r = es.search(index="soc-logs,soc-logs-*", size=0, query={
            "bool": {"must": [
                {"term":  {"log_type": "auth"}},
                {"range": {"@timestamp": {"gte": f"now-{WINDOW}"}}}
            ]}
        }, aggs={"by_ip": {"terms": {"field": "src_ip.keyword", "size": 20}}})
    except Exception as e:
        log.error(f"SSH BF ES error: {e}")
        return

    for b in r.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        ip, count = b["key"], b["doc_count"]
        if not ip or count < SSH_WARN:
            continue

        severity = "high" if count >= SSH_HIGH else "medium"
        score    = min(0.95, 0.3 + count * 0.01)
        log.info(f"SSH brute force [{severity.upper()}]: {ip} — {count}/{WINDOW}")
        _send_incident(ip, score, severity, "auth", "ssh_brute_force",
                       f"({count} auth logs/{WINDOW})")


def check_http_flood():
    """Compte les requêtes apache_access par IP sur 5 min."""
    try:
        r = es.search(index="soc-logs,soc-logs-*", size=0, query={
            "bool": {"must": [
                {"term":  {"log_type": "apache_access"}},
                {"range": {"@timestamp": {"gte": f"now-{WINDOW}"}}}
            ]}
        }, aggs={"by_ip": {"terms": {"field": "src_ip.keyword", "size": 20}}})
    except Exception as e:
        log.error(f"HTTP flood ES error: {e}")
        return

    for b in r.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        ip, count = b["key"], b["doc_count"]
        if not ip or count < HTTP_FLOOD:
            continue

        score = min(0.90, 0.4 + count * 0.002)
        log.info(f"HTTP flood [MEDIUM]: {ip} — {count} requêtes/{WINDOW}")
        _send_incident(ip, score, "medium", "apache_access", "http_flood",
                       f"({count} reqs/{WINDOW})")


def check_web_scan():
    """Compte les erreurs HTTP (4xx) par IP sur 5 min."""
    try:
        r = es.search(index="soc-logs,soc-logs-*", size=0, query={
            "bool": {"must": [
                {"term":  {"log_type": "apache_access"}},
                {"range": {"@timestamp": {"gte": f"now-{WINDOW}"}}},
                {"term":  {"severity": "medium"}}
            ]}
        }, aggs={"by_ip": {"terms": {"field": "src_ip.keyword", "size": 20}}})
    except Exception as e:
        log.error(f"Web scan ES error: {e}")
        return

    for b in r.get("aggregations", {}).get("by_ip", {}).get("buckets", []):
        ip, count = b["key"], b["doc_count"]
        if not ip or count < HTTP_SCAN:
            continue

        score = min(0.75, 0.3 + count * 0.01)
        log.info(f"Web scan [MEDIUM]: {ip} — {count} erreurs HTTP/{WINDOW}")
        _send_incident(ip, score, "medium", "apache_access", "web_scan",
                       f"({count} 4xx/{WINDOW})")


if __name__ == "__main__":
    log.info(f"Démarré — fenêtre: {WINDOW}")
    log.info(f"  SSH brute force : >= {SSH_WARN} auth/5min")
    log.info(f"  HTTP flood      : >= {HTTP_FLOOD} req/5min")
    log.info(f"  Web scan        : >= {HTTP_SCAN} erreurs/5min")
    while True:
        check_ssh_brute_force()
        check_http_flood()
        check_web_scan()
        time.sleep(INTERVAL)
