#!/bin/bash
echo "[*] Arrêt des services SOC..."

# Tuer par nom de script
pkill -9 -f "app\.py"         2>/dev/null && echo "  Flask arrêté"          || true
pkill -9 -f "ia_detector"     2>/dev/null && echo "  IA Detector arrêté"    || true
pkill -9 -f "cve_scanner"     2>/dev/null && echo "  CVE Scanner arrêté"    || true
pkill -9 -f "rate_detector"   2>/dev/null && echo "  Rate Detector arrêté"  || true

# Libérer le port 5000 si encore occupé
PID_5000=$(lsof -ti :5000 2>/dev/null)
if [ -n "$PID_5000" ]; then
    kill -9 $PID_5000 2>/dev/null
    echo "  Port 5000 libéré (PID $PID_5000)"
fi

sleep 1

REMAINING=$(pgrep -a python3 2>/dev/null | grep -E "app\.py|ia_detector|cve_scanner|rate_detector")
if [ -n "$REMAINING" ]; then
    echo "[!] Processus encore actifs :"
    echo "$REMAINING"
else
    echo "[✓] Tous les services arrêtés."
fi
