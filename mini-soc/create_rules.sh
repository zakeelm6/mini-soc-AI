#!/bin/bash
# create_rules.sh — Crée uniquement les règles d'alerte (Kibana déjà configuré)

KIBANA="http://192.168.50.10:5601"
AUTH="elastic:changeme"

echo "[*] Création des règles d'alerte Kibana..."

# Règle 1 — SSH Brute Force
curl -s -X POST "${KIBANA}/api/alerting/rule" \
  -u "${AUTH}" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "name": "SOC — SSH Brute Force",
    "rule_type_id": ".index-threshold",
    "consumer": "alerts",
    "schedule": {"interval": "1m"},
    "params": {
      "index": ["soc-logs-*"],
      "timeField": "@timestamp",
      "aggType": "count",
      "groupBy": "all",
      "timeWindowSize": 5,
      "timeWindowUnit": "m",
      "thresholdComparator": ">",
      "threshold": [10],
      "filterKuery": "tags:\"ssh_failed\""
    },
    "actions": []
  }' | python3 -c "import sys,json; r=json.load(sys.stdin); print('  SSH Brute Force:', r.get('id','ERROR'), r.get('message','ok'))"

# Règle 2 — Anomalie IA critique
curl -s -X POST "${KIBANA}/api/alerting/rule" \
  -u "${AUTH}" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "name": "SOC — Anomalie IA critique",
    "rule_type_id": ".index-threshold",
    "consumer": "alerts",
    "schedule": {"interval": "2m"},
    "params": {
      "index": ["soc-anomalies"],
      "timeField": "@timestamp",
      "aggType": "max",
      "aggField": "anomaly_score",
      "groupBy": "all",
      "timeWindowSize": 5,
      "timeWindowUnit": "m",
      "thresholdComparator": ">=",
      "threshold": [0.7]
    },
    "actions": []
  }' | python3 -c "import sys,json; r=json.load(sys.stdin); print('  Anomalie IA:', r.get('id','ERROR'), r.get('message','ok'))"

# Règle 3 — CVE critique
curl -s -X POST "${KIBANA}/api/alerting/rule" \
  -u "${AUTH}" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "name": "SOC — CVE critique (CVSS ≥ 7)",
    "rule_type_id": ".index-threshold",
    "consumer": "alerts",
    "schedule": {"interval": "10m"},
    "params": {
      "index": ["soc-cve-alerts"],
      "timeField": "@timestamp",
      "aggType": "max",
      "aggField": "cvss",
      "groupBy": "all",
      "timeWindowSize": 60,
      "timeWindowUnit": "m",
      "thresholdComparator": ">=",
      "threshold": [7.0]
    },
    "actions": []
  }' | python3 -c "import sys,json; r=json.load(sys.stdin); print('  CVE critique:', r.get('id','ERROR'), r.get('message','ok'))"

echo ""
TOTAL=$(curl -s -u "${AUTH}" "${KIBANA}/api/alerting/rules/_find?per_page=10" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('total',0))")
echo "=== Règles actives : ${TOTAL} ==="
echo "Voir : ${KIBANA}/app/management/insightsAndAlerting/triggersActions/rules"
