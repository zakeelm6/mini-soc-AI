#!/bin/bash
# setup_geoip.sh — Active GeoIP dans le pipeline Logstash
# Nécessite sudo

set -e

PIPELINE="/etc/logstash/conf.d/soc-pipeline.conf"

echo "[1/3] Sauvegarde du pipeline actuel..."
sudo cp "${PIPELINE}" "${PIPELINE}.bak"
echo "      Sauvegarde : ${PIPELINE}.bak"

echo "[2/3] Injection du filtre GeoIP..."
sudo python3 - <<'PYEOF'
import re

path = "/etc/logstash/conf.d/soc-pipeline.conf"
with open(path, "r") as f:
    content = f.read()

geoip_block = """
  # ===== GEOIP =====
  if [src_ip] and [src_ip] != "" {
    geoip {
      source => "src_ip"
      target => "geoip"
    }
  }
"""

# Insérer avant le bloc mutate final (remove_field)
marker = '  mutate {\n    remove_field => ["@version"]\n  }'
if "geoip {" not in content:
    content = content.replace(marker, geoip_block + "\n" + marker)
    with open(path, "w") as f:
        f.write(content)
    print("  GeoIP injecté.")
else:
    print("  GeoIP déjà présent — rien à faire.")
PYEOF

echo "[3/3] Redémarrage de Logstash..."
sudo systemctl restart logstash
echo "      Logstash redémarré."
echo ""
echo "=== GeoIP actif ==="
echo "Dans Kibana : créer une visualisation Maps avec le champ geoip.location"
echo "Les prochains logs avec src_ip auront un champ geoip.country_name et geoip.location"
