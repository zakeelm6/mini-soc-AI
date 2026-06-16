#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  Mini-SOC Watchdog — maintient Flask en vie, redémarre si crash
#  Usage : nohup bash watchdog.sh &
#  Log   : /tmp/watchdog.log
# ══════════════════════════════════════════════════════════════════

SOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="/home/arthur-leywin/mini-soc/venv/bin/python3"
LOG="/tmp/flask.log"
WATCHDOG_LOG="/tmp/watchdog.log"
RESTART_DELAY=3
MAX_RESTARTS=20

cd "$SOC_DIR"

_ts() { date '+%Y-%m-%d %H:%M:%S'; }
_log() { echo "[$(_ts)] $1" | tee -a "$WATCHDOG_LOG"; }

_log "=== Watchdog démarré (PID=$$) ==="
restarts=0

while [ $restarts -lt $MAX_RESTARTS ]; do
    # Tuer toute instance existante
    pkill -9 -f "app\.py" 2>/dev/null || true
    PID_5000=$(lsof -ti :5000 2>/dev/null)
    [ -n "$PID_5000" ] && kill -9 $PID_5000 2>/dev/null || true
    sleep 1

    _log "Lancement Flask (tentative $((restarts+1))/$MAX_RESTARTS)..."
    FLASK_DEBUG=0 $PYTHON -u app.py >> "$LOG" 2>&1 &
    FLASK_PID=$!
    echo $FLASK_PID > /tmp/flask.pid
    _log "Flask PID=$FLASK_PID"

    # Attendre la mort du process
    wait $FLASK_PID
    EXIT_CODE=$?
    restarts=$((restarts+1))

    _log "Flask s'est arrêté (exit=$EXIT_CODE) — redémarrage dans ${RESTART_DELAY}s..."
    sleep $RESTART_DELAY
done

_log "=== Watchdog arrêté après $MAX_RESTARTS redémarrages ==="
