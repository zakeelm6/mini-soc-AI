from elasticsearch import Elasticsearch
import requests
from datetime import datetime, timedelta
import time
from config import ES_HOST, ES_USER, ES_PASSWORD, FLASK_URL

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))
COMPOSANTS = ["apache", "openssh", "elasticsearch", "linux kernel",
              "suricata", "logstash", "kibana"]

def already_indexed(cve_id):
    """Déduplication persistante — vérifie ES, résiste aux redémarrages."""
    try:
        r = es.count(
            index="soc-cve-alerts",
            query={"term": {"cve_id.keyword": cve_id}}
        )
        return r["count"] > 0
    except Exception:
        return False

def scan_cves():
    end   = datetime.utcnow()
    start = end - timedelta(days=30)
    url   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "cvssV3Severity": "CRITICAL"
    }
    try:
        resp = requests.get(url, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"Erreur NVD : {e}")
        return

    new_count = 0
    for item in data.get("vulnerabilities", []):
        cve    = item["cve"]
        cve_id = cve["id"]

        if already_indexed(cve_id):
            continue

        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d["lang"] == "en"), "")
        if not any(kw in desc.lower() for kw in COMPOSANTS):
            continue

        cvss = 0.0
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in cve.get("metrics", {}):
                cvss = cve["metrics"][key][0]["cvssData"]["baseScore"]
                break
        if cvss < 9.0:
            continue

        print(f"Nouvelle CVE : {cve_id} (CVSS {cvss})")
        # champ unifié : cvss_score (plus de doublon cvss/cvss_score)
        es.index(index="soc-cve-alerts", document={
            "@timestamp":  datetime.utcnow().isoformat(),
            "cve_id":      cve_id,
            "cvss_score":  cvss,
            "description": desc
        })
        try:
            requests.post(f"{FLASK_URL}/api/auto_incident_cve", json={
                "cve_id":      cve_id,
                "cvss_score":  cvss,
                "description": desc
            }, timeout=3)
        except Exception:
            pass
        new_count += 1

    print(f"[{datetime.now()}] Scan CVE terminé — {new_count} nouvelle(s) CVE")

if __name__ == "__main__":
    print("CVE Scanner démarré...")
    while True:
        scan_cves()
        time.sleep(6 * 3600)
