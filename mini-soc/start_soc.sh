#!/bin/bash
# ─── Mini-SOC — Démarrage complet ─────────────────────────────────────────────
set -e
SOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SOC_DIR"
# Cherche le venv dans l'ordre : local → ~/mini-soc → ~/venv
if   [ -f "$SOC_DIR/venv/bin/activate" ];           then source "$SOC_DIR/venv/bin/activate"
elif [ -f "$HOME/mini-soc/venv/bin/activate" ];      then source "$HOME/mini-soc/venv/bin/activate"; PYTHON="$HOME/mini-soc/venv/bin/python3"
elif [ -f "$HOME/venv/bin/activate" ];               then source "$HOME/venv/bin/activate"
else echo "Aucun venv trouvé, utilisation du python3 système"; fi
PYTHON="${PYTHON:-python3}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; }
err()  { echo -e "  ${RED}✗${NC} $1"; }
info() { echo -e "  ${BLUE}→${NC} $1"; }

echo ""
echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        Mini-SOC — Démarrage          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

# ── 1. Services système ────────────────────────────────────────────────────────
echo "[ Services système ]"

# Elasticsearch
if systemctl is-active --quiet elasticsearch 2>/dev/null; then
    ok "Elasticsearch déjà actif"
else
    info "Démarrage Elasticsearch..."
    sudo systemctl start elasticsearch 2>/dev/null && ok "Elasticsearch démarré" || warn "Elasticsearch non démarré (sudo requis ?)"
fi

# Logstash
if systemctl is-active --quiet logstash 2>/dev/null; then
    ok "Logstash déjà actif"
else
    info "Démarrage Logstash..."
    sudo systemctl start logstash 2>/dev/null && ok "Logstash démarré" || warn "Logstash non démarré"
fi

# Kibana
if systemctl is-active --quiet kibana 2>/dev/null; then
    ok "Kibana déjà actif"
else
    info "Démarrage Kibana..."
    sudo systemctl start kibana 2>/dev/null && ok "Kibana démarré" || warn "Kibana non démarré"
fi

# Ollama
if systemctl is-active --quiet ollama 2>/dev/null; then
    ok "Ollama déjà actif"
else
    info "Démarrage Ollama..."
    sudo systemctl start ollama 2>/dev/null && ok "Ollama démarré" || warn "Ollama non démarré"
fi

echo ""
echo "[ Agents Python ]"

# ── 2. Arrêter les anciennes instances ────────────────────────────────────────
pkill -9 -f "app\.py"       2>/dev/null || true
pkill -9 -f "ia_detector"   2>/dev/null || true
pkill -9 -f "cve_scanner"   2>/dev/null || true
pkill -9 -f "rate_detector" 2>/dev/null || true
PID_5000=$(lsof -ti :5000 2>/dev/null) && [ -n "$PID_5000" ] && kill -9 $PID_5000 2>/dev/null || true
sleep 1

# ── 3. Lancer les agents ──────────────────────────────────────────────────────
FLASK_DEBUG=0 $PYTHON -u app.py        > /tmp/flask.log 2>&1 & echo $! > /tmp/flask.pid
$PYTHON -u ia_detector.py              > /tmp/ia.log    2>&1 & echo $! > /tmp/ia.pid
$PYTHON -u cve_scanner.py             > /tmp/cve.log   2>&1 & echo $! > /tmp/cve.pid
$PYTHON -u rate_detector.py           > /tmp/rate.log  2>&1 & echo $! > /tmp/rate.pid

sleep 3

# ── 4. Vérification ───────────────────────────────────────────────────────────
check_proc() {
    local name="$1" pattern="$2"
    pgrep -f "$pattern" > /dev/null 2>&1 && ok "$name" || err "$name (vérifier /tmp/$(echo $pattern | cut -d_ -f1).log)"
}
check_proc "Flask (app.py)"      "app\.py"
check_proc "IA Detector"         "ia_detector"
check_proc "CVE Scanner"         "cve_scanner"
check_proc "Rate Detector"       "rate_detector"

# ── 5. URLs ───────────────────────────────────────────────────────────────────
echo ""
echo "[ Accès ]"
TS_IP=$(tailscale ip -4 2>/dev/null || hostname -I | awk '{print $1}')
LOCAL_IP=$(hostname -I | awk '{print $1}')

printf "  %-22s %s\n" "Plateforme SOC"    "http://${TS_IP}:5000"
printf "  %-22s %s\n" "Kibana"            "http://${TS_IP}:5601"
printf "  %-22s %s\n" "Elasticsearch"     "http://localhost:9200"
[ "$TS_IP" != "$LOCAL_IP" ] && printf "  %-22s %s\n" "LAN (local)" "http://${LOCAL_IP}:5000"

echo ""
echo "[ Logs en direct ]"
printf "  %-22s %s\n" "Flask"        "tail -f /tmp/flask.log"
printf "  %-22s %s\n" "IA Detector"  "tail -f /tmp/ia.log"
printf "  %-22s %s\n" "CVE Scanner"  "tail -f /tmp/cve.log"
printf "  %-22s %s\n" "Rate Detect"  "tail -f /tmp/rate.log"
echo ""
