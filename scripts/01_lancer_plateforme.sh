#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  Mini-SOC — Lancement complet de la plateforme
#  Usage : bash 01_lancer_plateforme.sh
# ══════════════════════════════════════════════════════════════════
set -e

SOC_DIR="/home/arthur-leywin/Documents/project-pfa/mini-soc"
VENV="/home/arthur-leywin/mini-soc/venv/bin/python3"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; }
err()  { echo -e "  ${RED}✗${NC} $1"; }
info() { echo -e "  ${BLUE}→${NC} $1"; }

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       Mini-SOC — Démarrage complet       ║${NC}"
echo -e "${CYAN}║       PFA 2025-2026 · INPT               ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Services système ─────────────────────────────────────────
echo -e "${BLUE}[ 1/3 ] Services système${NC}"

for svc in elasticsearch logstash kibana; do
    if systemctl is-active --quiet $svc 2>/dev/null; then
        ok "$svc déjà actif"
    else
        info "Démarrage $svc..."
        sudo systemctl start $svc 2>/dev/null && ok "$svc démarré" || warn "$svc non démarré (sudo requis ?)"
    fi
done

# Ollama
if pgrep -f "ollama serve" > /dev/null 2>&1; then
    ok "Ollama déjà actif"
else
    info "Démarrage Ollama..."
    sudo systemctl start ollama 2>/dev/null || ollama serve > /tmp/ollama.log 2>&1 &
    sleep 2
    pgrep -f ollama > /dev/null && ok "Ollama démarré" || warn "Ollama non démarré"
fi

echo ""
echo -e "${BLUE}[ 2/3 ] Agents Python${NC}"

# ── 2. Tuer les anciennes instances ─────────────────────────────
pkill -9 -f "app\.py"       2>/dev/null || true
pkill -9 -f "ia_detector"   2>/dev/null || true
pkill -9 -f "cve_scanner"   2>/dev/null || true
pkill -9 -f "rate_detector" 2>/dev/null || true
PID_5000=$(lsof -ti :5000 2>/dev/null) && [ -n "$PID_5000" ] && kill -9 $PID_5000 2>/dev/null || true
sleep 1

# ── 3. Lancer les agents ─────────────────────────────────────────
cd "$SOC_DIR"

# Flask via watchdog (auto-restart si crash)
pkill -f "watchdog.sh" 2>/dev/null || true
sleep 1
nohup bash "$(dirname "$0")/watchdog_flask.sh" > /tmp/watchdog.log 2>&1 &
WDOG_PID=$!
disown $WDOG_PID
echo $WDOG_PID > /tmp/watchdog.pid
info "Watchdog Flask lancé (PID=$WDOG_PID) — redémarre Flask automatiquement"

$VENV -u ia_detector.py               > /tmp/ia.log    2>&1 & echo $! > /tmp/ia.pid
$VENV -u cve_scanner.py               > /tmp/cve.log   2>&1 & echo $! > /tmp/cve.pid
$VENV -u rate_detector.py             > /tmp/rate.log  2>&1 & echo $! > /tmp/rate.pid

sleep 5

echo ""
echo -e "${BLUE}[ 3/3 ] Vérification${NC}"
pgrep -f "app\.py"      > /dev/null && ok "Flask (app.py) — watchdog actif" || err "Flask DOWN — voir /tmp/flask.log"
pgrep -f "ia_detector"  > /dev/null && ok "IA Detector"          || err "IA Detector DOWN"
pgrep -f "cve_scanner"  > /dev/null && ok "CVE Scanner"          || err "CVE Scanner DOWN"
pgrep -f "rate_detector"> /dev/null && ok "Rate Detector"        || err "Rate Detector DOWN"

# ── Adresses ─────────────────────────────────────────────────────
echo ""
TS_IP=$(tailscale ip -4 2>/dev/null || hostname -I | awk '{print $1}')
LOCAL_IP=$(hostname -I | awk '{print $1}')
echo -e "${CYAN}[ Accès ]${NC}"
printf "  %-22s ${GREEN}%s${NC}\n" "Plateforme SOC"  "http://${TS_IP}:5000"
printf "  %-22s %s\n"              "Kibana"           "http://${TS_IP}:5601"
printf "  %-22s %s\n"              "Elasticsearch"    "http://localhost:9200"

echo ""
echo -e "${CYAN}[ Logs en direct ]${NC}"
printf "  %-18s tail -f /tmp/watchdog.log\n" "Watchdog"
printf "  %-18s tail -f /tmp/flask.log\n"  "Flask"
printf "  %-18s tail -f /tmp/ia.log\n"     "IA Detector"
printf "  %-18s tail -f /tmp/cve.log\n"    "CVE Scanner"
printf "  %-18s tail -f /tmp/rate.log\n"   "Rate Detect"
echo ""
