#!/bin/bash
# setup_kibana_alerting.sh — Active les alertes Kibana + crée les règles SOC
# Usage : bash setup_kibana_alerting.sh
# Nécessite : sudo (pour modifier kibana.yml)

set -e

KIBANA="http://192.168.50.10:5601"
AUTH="elastic:changeme"
FLASK="http://localhost:5000"

# ─── Étape 1 : clé de chiffrement ─────────────────────────────────────────────
echo "[1/4] Ajout de la clé de chiffrement dans kibana.yml..."

KEY=$(openssl rand -hex 16)
echo "xpack.encryptedSavedObjects.encryptionKey: ${KEY}" | sudo tee -a /etc/kibana/kibana.yml

echo "      Clé ajoutée : ${KEY}"

# ─── Étape 2 : redémarrage Kibana ─────────────────────────────────────────────
echo "[2/4] Redémarrage de Kibana (attente 40s)..."
sudo systemctl restart kibana
sleep 40

# Attendre que Kibana réponde
for i in $(seq 1 12); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -u "${AUTH}" "${KIBANA}/api/status")
    if [ "$STATUS" = "200" ]; then
        echo "      Kibana opérationnel ✓"
        break
    fi
    echo "      Attente... ($i/12)"
    sleep 10
done

# ─── Étape 3 : créer les règles d'alerte ──────────────────────────────────────
echo "[3/4] Création des règles d'alerte Kibana..."

# Règle 1 — SSH Brute Force (> 10 échecs SSH en 5 min)
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

# Règle 2 — Anomalie IA critique (score ≥ 0.7)
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

# Règle 3 — CVE critique (CVSS ≥ 7)
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

# ─── Étape 4 : vérification ────────────────────────────────────────────────────
echo "[4/4] Vérification..."
HEALTH=$(curl -s -u "${AUTH}" "${KIBANA}/api/alerting/_health" | python3 -c "import sys,json; r=json.load(sys.stdin); print('  has_permanent_encryption_key:', r.get('has_permanent_encryption_key'))")
echo "${HEALTH}"

RULES=$(curl -s -u "${AUTH}" "${KIBANA}/api/alerting/rules/_find?per_page=10" | python3 -c "import sys,json; r=json.load(sys.stdin); print('  Règles créées:', r.get('total',0))")
echo "${RULES}"

echo ""
echo "=== Terminé ==="
echo "Kibana Alerting : ${KIBANA}/app/management/insightsAndAlerting/triggersActions/rules"
