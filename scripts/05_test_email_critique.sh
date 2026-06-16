#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  Test email — vérifie que les incidents critiques envoient
#  un email au L3 (admin) dès la création
# ══════════════════════════════════════════════════════════════════

VENV="/opt/mini-soc/venv/bin/python3"
SOC_DIR="/opt/mini-soc"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo "[ Test email — incident CRITIQUE → L3 ]"
echo ""

cd "$SOC_DIR"
$VENV - <<'EOF'
import sys, json
sys.path.insert(0, '.')
import notifier

print("Config email actuelle :")
cfg = notifier._load_config()
ecfg = cfg.get("email", {})
print(f"  SMTP : {ecfg.get('smtp_host')}:{ecfg.get('smtp_port')} (SSL={ecfg.get('use_ssl', False)})")
print(f"  User : {ecfg.get('smtp_user')}")
print(f"  Enabled : {ecfg.get('enabled')}")
print()

# Charger les users
users = notifier._load_users()
print("Utilisateurs et emails :")
for u, d in users.items():
    print(f"  {u:15} level={d.get('level','?'):8} email={d.get('email','(vide)')}")
print()

# Test incident critique → doit aller vers L3
inc_critical = {
    'incident_id':   'DEMO-CRIT-001',
    'title':         '[IA] auth — score 9.8/10 — 192.168.122.114',
    'severity':      'critical',
    'src_ip':        '192.168.122.114',
    'attack_type':   'brute_force',
    'assigned_to':   'admin',
    'anomaly_score': 0.98,
    'log_type':      'ia',
    'created_at':    '2026-06-08T10:00:00',
}

email, user = notifier.get_recipient(inc_critical)
print(f"Destinataire résolu pour incident CRITIQUE :")
print(f"  → email : {email}")
print(f"  → niveau: {user.get('level') if user else '?'}")
print()

print("Envoi de l'email test...")
ok = notifier.send_email('new_incident', inc_critical)
if ok:
    print(f"\033[0;32m  ✓ Email envoyé avec succès → {email}\033[0m")
else:
    print(f"\033[0;31m  ✗ Échec envoi email\033[0m")

# Test incident HIGH → L2
print()
inc_high = {**inc_critical,
    'incident_id': 'DEMO-HIGH-001',
    'title': '[Ensemble] HIGH — score 7.2/10 — 192.168.122.114',
    'severity': 'high',
    'assigned_to': 'analyst_l2',
    'anomaly_score': 0.72,
}
email2, user2 = notifier.get_recipient(inc_high)
print(f"Destinataire pour incident HIGH :")
print(f"  → email : {email2}")
print(f"  → niveau: {user2.get('level') if user2 else '?'}")
ok2 = notifier.send_email('new_incident', inc_high)
if ok2:
    print(f"\033[0;32m  ✓ Email HIGH envoyé → {email2}\033[0m")
else:
    print(f"\033[0;31m  ✗ Échec email HIGH\033[0m")
EOF
