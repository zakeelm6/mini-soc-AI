#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  Reset démo — nettoyer les incidents avant une démonstration
#  Usage : bash 00_reset_demo.sh
# ══════════════════════════════════════════════════════════════════

ES_URL="http://localhost:9200"
ES_USER="elastic"
ES_PASS="${ES_PASSWORD:-changeme}"
AUTH="-u ${ES_USER}:${ES_PASS}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()  { echo -e "  ${GREEN}✓${NC} $1"; }
err() { echo -e "  ${RED}✗${NC} $1"; }

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════╗"
echo "║   RESET DÉMO — Nettoyage avant démo   ║"
echo -e "╚══════════════════════════════════════╝${NC}"
echo ""

# 1. Compter les incidents avant reset
COUNT=$(curl -s $AUTH "$ES_URL/soc-incidents/_count" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
echo "  Incidents actuels : $COUNT"

# 2. Fermer (ne pas supprimer) les incidents existants — marquer comme "archived"
curl -s $AUTH -X POST "$ES_URL/soc-incidents/_update_by_query" \
     -H "Content-Type: application/json" \
     -d '{"query":{"match_all":{}},"script":{"source":"ctx._source.status=\"archived\";ctx._source.archived_at=params.ts","params":{"ts":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}}' \
     > /dev/null 2>&1
ok "Incidents existants archivés (pas supprimés)"

# 3. Supprimer les IPs bloquées de la session précédente (iptables)
iptables -F INPUT 2>/dev/null && ok "iptables INPUT nettoyé" || true

# 4. Vérifier les services
echo ""
echo "  Vérification services :"
pgrep -f ia_detector  > /dev/null && ok "IA Detector actif"   || err "IA Detector DOWN — relancer 01_lancer_plateforme.sh"
pgrep -f rate_detector> /dev/null && ok "Rate Detector actif" || err "Rate Detector DOWN"
pgrep -f watchdog     > /dev/null && ok "Watchdog Flask actif" || err "Watchdog DOWN"
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/ | grep -q "302\|200" && ok "Flask répond (port 5000)" || err "Flask DOWN"
curl -s $AUTH "$ES_URL/_cluster/health" | python3 -c "import sys,json;h=json.load(sys.stdin);print(f'  \033[0;32m✓\033[0m Elasticsearch {h[\"status\"]} ({h[\"active_shards\"]} shards)')" 2>/dev/null

# 5. Vérifier VM victime / attaquant (adapter les IPs à votre lab)
VICTIM_IP="${VICTIM_IP:-192.168.122.20}"
ATTACKER_IP="${ATTACKER_IP:-192.168.122.30}"
ping -c1 -W2 "$VICTIM_IP" > /dev/null 2>&1 && ok "VM Victime ($VICTIM_IP) accessible" || err "VM Victime DOWN"
ping -c1 -W2 "$ATTACKER_IP" > /dev/null 2>&1 && ok "VM Attaquant ($ATTACKER_IP) accessible" || err "VM Attaquant DOWN"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗"
echo "║  PRÊT POUR LA DÉMO                                   ║"
echo "║                                                      ║"
echo "║  1. Ouvrir Firefox → http://localhost:5000           ║"
echo "║     Login: admin / ChangeMe123!                      ║"
echo "║  2. SSH attaquant : ssh <user>@\$ATTACKER_IP           ║"
echo "║  3. Sur attaquant : lancer un scénario d'attaque     ║"
echo -e "╚══════════════════════════════════════════════════════╝${NC}"
echo ""
