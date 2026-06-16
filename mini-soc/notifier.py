"""
notifier.py — Notifications Email personnalisées par type d'attaque

Routage :
  CRITICAL → L3 + L2 + analyste assigné
  HIGH     → analyste assigné + supérieur direct (L2)
  MEDIUM   → analyste assigné uniquement
  LOW      → personne

Email personnalisé selon attack_type llama3 :
  SSH Brute Force, Web Attack, CVE Exploit, Port Scan,
  Lateral Movement, Ransomware, Data Exfil, Générique
"""
import json
import logging
import os
import smtplib
import threading
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

log = logging.getLogger("notifier")

NOTIF_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "notifications.json")
USERS_PATH        = os.path.join(os.path.dirname(__file__), "users.json")

_DEFAULT_CONFIG = {
    "enabled": True,
    "notify_severities": ["critical", "high"],
    "notify_on_assign":   True,
    "notify_on_escalate": True,
    "notify_on_sla_breach": True,
    "email": {
        "enabled":   False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_pass": "",
        "from_addr": "",
        "to_addrs":  [],
    },
    "webhook": {
        "enabled": False,
        "url":     "",
        "type":    "slack",
    },
}

_SEV_COLORS = {"critical": "#f85149", "high": "#ffa657", "medium": "#e3b341", "low": "#3fb950"}
_SEV_EMOJI  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
_LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3}

# ─── Playbooks par type d'attaque ────────────────────────────────────────────
# Chaque entrée : liste d'étapes concrètes avec commandes si possible
_ATTACK_PLAYBOOKS = {
    "ssh brute force": {
        "icon":  "🔑",
        "title": "SSH Brute Force",
        "steps": [
            ("Bloquer l'IP immédiatement",
             "sudo iptables -A INPUT -s {ip} -j DROP\nsudo iptables -A OUTPUT -d {ip} -j DROP"),
            ("Vérifier les connexions réussies",
             "grep 'Accepted' /var/log/auth.log | grep {ip}\nlast | grep {ip}"),
            ("Bannir via fail2ban",
             "sudo fail2ban-client set sshd banip {ip}"),
            ("Vérifier si des comptes ont été compromis",
             "grep 'Accepted password' /var/log/auth.log | tail -20\nwho -a"),
            ("Renforcer SSH si besoin",
             "# Désactiver auth par mot de passe :\nsudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config\nsudo systemctl restart sshd"),
        ]
    },
    "web attack": {
        "icon":  "🌐",
        "title": "Attaque Web",
        "steps": [
            ("Bloquer l'IP au niveau nginx/WAF",
             "# Ajouter dans nginx.conf :\ndeny {ip};\n# Puis recharger :\nsudo nginx -s reload"),
            ("Analyser les requêtes suspectes",
             "sudo grep {ip} /var/log/nginx/access.log | tail -50\nsudo grep {ip} /var/log/apache2/access.log 2>/dev/null | tail -50"),
            ("Vérifier les injections SQL/XSS",
             "grep -i 'union\\|select\\|script\\|<img\\|onerror' /var/log/nginx/access.log | grep {ip}"),
            ("Vérifier l'intégrité des fichiers web",
             "find /var/www -newer /var/www/index.html -type f\nls -la /var/www/html/"),
            ("Bloquer au firewall",
             "sudo ufw deny from {ip} to any"),
        ]
    },
    "sql injection": {
        "icon":  "💉",
        "title": "Injection SQL",
        "steps": [
            ("Bloquer l'IP en urgence",
             "sudo iptables -A INPUT -s {ip} -j DROP"),
            ("Analyser les requêtes malveillantes",
             "grep -i 'union\\|select\\|drop\\|insert\\|delete\\|--' /var/log/nginx/access.log | grep {ip}"),
            ("Vérifier l'intégrité de la base de données",
             "# Vérifier les tables critiques, chercher des données exfiltrées"),
            ("Activer le WAF ModSecurity",
             "sudo a2enmod security2\nsudo systemctl restart apache2"),
            ("Changer les credentials DB si compromis",
             "# Révoquer l'accès DB de l'application, régénérer les mots de passe"),
        ]
    },
    "cve": {
        "icon":  "🐛",
        "title": "Exploitation CVE",
        "steps": [
            ("Isoler la machine compromise",
             "sudo iptables -I INPUT -s {ip} -j DROP\nsudo iptables -I OUTPUT -d {ip} -j DROP"),
            ("Identifier le service vulnérable et patcher",
             "sudo apt update && sudo apt upgrade -y\nsudo snap refresh"),
            ("Vérifier les processus anormaux",
             "ps aux | grep -v root | awk '$3 > 10.0'\nnetstat -tlnp | grep -v ESTABLISHED"),
            ("Scanner les backdoors",
             "sudo rkhunter --check\nsudo chkrootkit"),
            ("Vérifier les crontabs et services",
             "crontab -l\nsudo systemctl list-units --state=failed\ncat /etc/crontab"),
        ]
    },
    "port scan": {
        "icon":  "🔍",
        "title": "Scan de ports",
        "steps": [
            ("Bloquer l'IP du scanner",
             "sudo iptables -A INPUT -s {ip} -j DROP\nsudo ufw deny from {ip}"),
            ("Analyser les ports scannés",
             "sudo tcpdump -i any src {ip} -c 100\ngrep {ip} /var/log/ufw.log | tail -30"),
            ("Vérifier si un port sensible a été trouvé",
             "sudo nmap -sV localhost  # voir ce qui est exposé\nsudo netstat -tlnp"),
            ("Activer les règles Suricata anti-scan",
             "sudo suricata-update\nsudo systemctl restart suricata"),
            ("Réduire la surface d'attaque",
             "sudo ufw default deny incoming\nsudo ufw allow 22/tcp\nsudo ufw enable"),
        ]
    },
    "lateral movement": {
        "icon":  "↔️",
        "title": "Mouvement Latéral",
        "steps": [
            ("Isoler les machines concernées",
             "# Bloquer les communications internes suspectes\nsudo iptables -A FORWARD -s {ip} -j DROP"),
            ("Identifier les comptes utilisés",
             "grep 'Accepted' /var/log/auth.log | grep -v 'from 192.168.'\nlast -n 50"),
            ("Révoquer les sessions actives suspectes",
             "who -a\nkill -9 $(ps -ef | grep sshd | grep {ip} | awk '{print $2}')"),
            ("Changer tous les mots de passe",
             "# Forcer le changement de password pour tous les comptes\npasswd -e <username>"),
            ("Analyser les logs de connexion réseau",
             "sudo journalctl -u ssh --since '1 hour ago'\nnetstat -an | grep ESTABLISHED"),
        ]
    },
    "ransomware": {
        "icon":  "🔒",
        "title": "Ransomware",
        "steps": [
            ("ISOLER la machine immédiatement — déconnecter du réseau",
             "sudo ip link set eth0 down\n# Ou physiquement débrancher le câble réseau"),
            ("Ne PAS payer la rançon — contacter le CERT",
             "# CERT-FR : cert-fr.gouv.fr\n# signalement-spam.fr pour signalement"),
            ("Identifier les fichiers chiffrés",
             "find / -name '*.locked' -o -name '*.encrypted' -o -name '*.ransom' 2>/dev/null\nfind / -newer /tmp -name '*.txt' 2>/dev/null | head -20"),
            ("Restaurer depuis le dernier backup propre",
             "# Vérifier le backup : ls -la /backup/\n# Ne pas restaurer sur une machine encore compromise"),
            ("Analyser le vecteur d'entrée",
             "grep 'Accepted' /var/log/auth.log | tail -20\nls -la /tmp/ /var/tmp/"),
        ]
    },
    "data exfiltration": {
        "icon":  "📤",
        "title": "Exfiltration de données",
        "steps": [
            ("Bloquer les transferts sortants depuis l'IP",
             "sudo iptables -A OUTPUT -s {ip} -j DROP\nsudo iptables -A OUTPUT -d {ip} -j DROP"),
            ("Analyser le volume de données transférées",
             "sudo iftop -i eth0 -f 'host {ip}'\nnetstat -s | grep 'segments sent'"),
            ("Identifier les fichiers/données accédés",
             "sudo ausearch -i -m file_rule --start today\nfind / -atime -1 -type f 2>/dev/null | grep -v proc"),
            ("Notifier le DPO (RGPD) si données personnelles",
             "# Délai légal : 72h pour notifier la CNIL si données personnelles"),
            ("Bloquer les ports d'exfiltration courants",
             "sudo iptables -A OUTPUT -p tcp --dport 21 -j DROP  # FTP\nsudo iptables -A OUTPUT -p tcp --dport 443 -d {ip} -j DROP"),
        ]
    },
    "default": {
        "icon":  "⚠️",
        "title": "Activité Suspecte",
        "steps": [
            ("Bloquer l'IP suspecte",
             "sudo iptables -A INPUT -s {ip} -j DROP"),
            ("Analyser les logs récents",
             "grep {ip} /var/log/syslog | tail -30\ngrep {ip} /var/log/auth.log | tail -20"),
            ("Vérifier les processus et connexions actives",
             "ps aux --sort=-%cpu | head -15\nnetstat -an | grep {ip}"),
            ("Investiguer manuellement dans Kibana",
             "# Kibana Discover → filtrer src_ip: {ip}"),
        ]
    },
}

SLA_MINUTES = {"critical": 15, "high": 60, "medium": 240, "low": 1440}


# ─── CONFIG ──────────────────────────────────────────────────────────────────

def load_config():
    try:
        with open(NOTIF_CONFIG_PATH) as f:
            cfg = json.load(f)
        for k, v in _DEFAULT_CONFIG.items():
            if k not in cfg:
                cfg[k] = v
            elif isinstance(v, dict):
                for k2, v2 in v.items():
                    if k2 not in cfg[k]:
                        cfg[k][k2] = v2
        return cfg
    except Exception:
        return _DEFAULT_CONFIG.copy()


def save_config(cfg):
    with open(NOTIF_CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def _load_users():
    try:
        with open(USERS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


# ─── ROUTAGE DES DESTINATAIRES ────────────────────────────────────────────────

def get_recipient(incident):
    """
    Retourne (email, user_data) de la seule personne concernée par cet incident.

    Règle : l'email va UNIQUEMENT à la personne assignée (ou au meilleur candidat
    selon le niveau requis par la sévérité si pas encore assigné).

    L1 → LOW, MEDIUM
    L2 → HIGH
    L3 → CRITICAL
    """
    sev      = incident.get("severity", "medium")
    assigned = incident.get("assigned_to", "")
    users    = _load_users()

    SEV_LEVEL = {
        "critical": "L3",
        "high":     "L2",
        "medium":   "L1",
        "low":      "L1",
    }
    needed_level = SEV_LEVEL.get(sev, "L1")

    # 1. Si un analyste est déjà assigné et actif → lui envoyer
    if assigned and assigned not in ("None", ""):
        for u in users.values():
            e = u.get("email", "").strip()
            if (u.get("name") == assigned
                    and u.get("active", True)
                    and e
                    and not e.endswith(".local")):
                return e, u

    # 2. Sinon → meilleur candidat actif du niveau requis
    def _real_email(u):
        e = u.get("email", "").strip()
        return e and not e.endswith(".local")

    candidates = [u for u in users.values()
                  if u.get("active", True)
                  and u.get("level") == needed_level
                  and _real_email(u)]
    # Fallback niveau supérieur si personne disponible
    if not candidates:
        for lvl in ["L2", "L3", "L1"]:
            candidates = [u for u in users.values()
                          if u.get("active", True)
                          and u.get("level") == lvl
                          and _real_email(u)]
            if candidates:
                break
    if candidates:
        return candidates[0]["email"].strip(), candidates[0]

    return None, None


def get_recipients(incident):
    """Compatibilité — retourne liste avec un seul destinataire."""
    email, _ = get_recipient(incident)
    return [email] if email else []


# ─── SÉLECTION DU PLAYBOOK ────────────────────────────────────────────────────

def _get_playbook(attack_type):
    if not attack_type:
        return _ATTACK_PLAYBOOKS["default"]
    at = attack_type.lower()
    for key, pb in _ATTACK_PLAYBOOKS.items():
        if key in at or any(w in at for w in key.split()):
            return pb
    return _ATTACK_PLAYBOOKS["default"]


def _sla_remaining(incident):
    sev = incident.get("severity", "medium")
    sla_min = SLA_MINUTES.get(sev, 240)
    try:
        created = datetime.fromisoformat(
            (incident.get("created_at") or "").replace("Z", "+00:00"))
        elapsed = (datetime.now(timezone.utc) - created).total_seconds() / 60
        remaining = sla_min - elapsed
        breached = remaining < 0
        return int(remaining), breached
    except Exception:
        return sla_min, False


# ─── CONSTRUCTION EMAIL HTML ──────────────────────────────────────────────────

def _build_email_html(event_type, incident, extra=None, recipient_user=None):
    sev          = incident.get("severity", "medium")
    color        = _SEV_COLORS.get(sev, "#8b949e")
    emoji        = _SEV_EMOJI.get(sev, "⚪")
    iid          = incident.get("incident_id", "—")
    title        = incident.get("title", "Incident SOC")
    ip           = incident.get("src_ip", "—")
    score        = incident.get("anomaly_score") or incident.get("unified_score") or "—"
    created      = (incident.get("created_at") or "")[:16].replace("T", " ")
    assigned     = incident.get("assigned_to") or "Non assigné"
    llm_verdict  = incident.get("llm_verdict") or "En attente d'analyse"
    votes        = incident.get("votes")

    # Nom du destinataire pour personnalisation
    recipient_name  = (recipient_user or {}).get("name", "") if recipient_user else ""
    recipient_level = (recipient_user or {}).get("level", "") if recipient_user else ""
    # Champ "Assigné à" : si le destinataire est différent de l'assigné d'origine
    # (routing de fallback), afficher le vrai destinataire
    if recipient_name and assigned not in (recipient_name, "Non assigné"):
        assigned_display = f"{recipient_name} (rerouté — {assigned} indisponible)"
    elif recipient_name:
        assigned_display = recipient_name
    else:
        assigned_display = assigned

    # Données llama3
    ai = incident.get("ai_analysis") or {}
    if not isinstance(ai, dict):
        ai = {}
    attack_type     = ai.get("attack_type") or incident.get("attack_type") or ""
    attacker_intent = ai.get("attacker_intent") or ""
    llm_summary     = ai.get("summary") or ""
    llm_evidence    = ai.get("evidence") or []
    llm_actions     = ai.get("actions") or []
    llm_confidence  = ai.get("confidence") or incident.get("llm_confidence") or 0
    threat_level    = ai.get("threat_level") or ""
    geoip           = incident.get("geoip") or {}
    geo_str         = f"{geoip.get('city','')}, {geoip.get('country','')}" if geoip.get("country") else ""

    # SLA
    sla_remaining, sla_breached = _sla_remaining(incident)
    if sla_breached:
        sla_html = f'<span style="color:#f85149;font-weight:700;">⚠️ SLA DÉPASSÉ de {abs(sla_remaining)}min</span>'
    elif sla_remaining < 15:
        sla_html = f'<span style="color:#ffa657;font-weight:700;">⏱ {sla_remaining}min restantes — URGENT</span>'
    else:
        h, m = divmod(sla_remaining, 60)
        sla_html = f'<span style="color:#3fb950;">{h}h{m:02d} restantes</span>'

    # Playbook
    playbook = _get_playbook(attack_type)
    pb_steps_html = ""
    for i, (step_title, commands) in enumerate(playbook["steps"], 1):
        cmds = commands.replace("{ip}", ip if ip != "—" else "X.X.X.X")
        pb_steps_html += f"""
        <div style="margin-bottom:14px;">
          <div style="font-size:12px;font-weight:700;color:#c9d1d9;margin-bottom:6px;">
            {i}. {step_title}
          </div>
          <pre style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;
                      font-family:monospace;font-size:11px;color:#79c0ff;margin:0;
                      white-space:pre-wrap;word-break:break-all;">{cmds}</pre>
        </div>"""

    # Preuves llama3
    evidence_html = ""
    if llm_evidence:
        items = "".join(f'<li style="margin-bottom:4px;color:#c9d1d9;">{e}</li>' for e in llm_evidence[:5])
        evidence_html = f"""
        <div style="margin-bottom:20px;">
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:{color};margin-bottom:8px;">
            Preuves détectées
          </div>
          <ul style="margin:0;padding-left:18px;font-size:12px;">{items}</ul>
        </div>"""

    # Scores IA
    if_s    = incident.get("if_score")
    rf_s    = incident.get("rf_score")
    dl_s    = incident.get("dl_score")
    rate    = incident.get("rate_count")
    scores_html = ""
    if any(v is not None for v in [if_s, rf_s, dl_s]):
        def bar(val, thresh):
            if val is None:
                return "N/A"
            pct = min(100, int(float(val) * 100))
            c = "#f85149" if float(val) >= thresh else "#3fb950"
            return f'<span style="color:{c};font-family:monospace;">{float(val):.3f}</span>'
        scores_html = f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;margin-bottom:20px;">
          <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#58a6ff;margin-bottom:8px;">
            Votes des modèles IA ({votes or "?"}/4 concordants)
          </div>
          <div style="display:flex;gap:20px;flex-wrap:wrap;font-size:11px;">
            <span>Isolation Forest : {bar(if_s, 0.25)}</span>
            <span>Random Forest : {bar(rf_s, 0.55)}</span>
            <span>Autoencoder DL : {bar(dl_s, 0.30)}</span>
            {"<span>Rate SSH : <span style='color:#ffa657;font-family:monospace;'>" + str(rate) + "</span>/5min</span>" if rate is not None else ""}
          </div>
        </div>"""

    event_labels = {
        "new_incident": "Incident qui vous est assigné",
        "assigned":     "Incident assigné — action requise",
        "escalated":    "⬆️ Incident escaladé — votre intervention requise",
        "sla_breach":   "⚠️ SLA dépassé — action urgente",
    }
    event_label = event_labels.get(event_type, event_type)
    conf_pct = int(float(llm_confidence) * 100) if llm_confidence else 0

    # Bannière personnalisée d'assignation
    greeting = f"Bonjour {recipient_name}," if recipient_name else "Bonjour,"
    SEV_MSG = {
        "critical": f"Un incident <strong>CRITIQUE</strong> vous a été assigné. Veuillez le prendre en charge immédiatement (SLA : {sla_html}).",
        "high":     f"Un incident <strong>HIGH</strong> vous a été assigné. Merci de le traiter dans les meilleurs délais (SLA : {sla_html}).",
        "medium":   f"Un incident <strong>MEDIUM</strong> vous a été assigné (SLA : {sla_html}).",
        "low":      f"Un incident <strong>LOW</strong> vous a été assigné pour analyse.",
    }
    assign_msg = SEV_MSG.get(sev, f"Un incident vous a été assigné (SLA : {sla_html}).")

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="margin:0;padding:20px;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;">
<div style="max-width:620px;margin:0 auto;">

  <!-- BANNIÈRE ASSIGNATION PERSONNALISÉE -->
  <div style="background:{color};border-radius:10px;padding:16px 22px;margin-bottom:14px;
              display:flex;align-items:center;gap:14px;">
    <div style="font-size:2rem;">{emoji}</div>
    <div>
      <div style="font-size:13px;font-weight:700;color:#ffffff;">{greeting}</div>
      <div style="font-size:12px;color:rgba(255,255,255,0.9);margin-top:3px;">{assign_msg}</div>
    </div>
  </div>

  <!-- HEADER -->
  <div style="background:{color}18;border:1px solid {color}44;border-top:4px solid {color};
              border-radius:10px;padding:20px 24px;margin-bottom:16px;">
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;
                color:{color};margin-bottom:6px;">{event_label}</div>
    <div style="font-size:22px;font-weight:800;color:#ffffff;margin-bottom:4px;">
      {playbook['icon']} {title}
    </div>
    <div style="font-size:12px;color:#8b949e;">
      {iid} · {created}
    </div>
  </div>

  <!-- INFOS CLÉS -->
  <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
              padding:16px 20px;margin-bottom:16px;">
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;
                color:#58a6ff;margin-bottom:12px;">Informations de l'incident</div>
    <table style="width:100%;border-collapse:collapse;font-size:12px;">
      <tr>
        <td style="padding:6px 0;color:#8b949e;width:160px;">IP Attaquante</td>
        <td style="padding:6px 0;color:#f85149;font-family:monospace;font-weight:700;">
          {ip}{f" · {geo_str}" if geo_str else ""}
        </td>
      </tr>
      <tr style="border-top:1px solid #21262d;">
        <td style="padding:6px 0;color:#8b949e;">Type d'attaque</td>
        <td style="padding:6px 0;color:#ffa657;font-weight:600;">
          {playbook['icon']} {attack_type or "En analyse…"}
        </td>
      </tr>
      <tr style="border-top:1px solid #21262d;">
        <td style="padding:6px 0;color:#8b949e;">Sévérité</td>
        <td style="padding:6px 0;">
          <span style="background:{color}22;color:{color};padding:2px 10px;
                       border-radius:10px;font-weight:700;font-size:11px;">
            {sev.upper()}
          </span>
          {f'<span style="margin-left:8px;font-size:11px;color:#8b949e;">Niveau menace : {threat_level}</span>' if threat_level else ""}
        </td>
      </tr>
      <tr style="border-top:1px solid #21262d;">
        <td style="padding:6px 0;color:#8b949e;">Score IA (ensemble)</td>
        <td style="padding:6px 0;color:#58a6ff;font-family:monospace;font-weight:600;">
          {float(score):.3f}/1.0 {f"· Confiance llama3 : {conf_pct}%" if conf_pct else ""}
        </td>
      </tr>
      <tr style="border-top:1px solid #21262d;">
        <td style="padding:6px 0;color:#8b949e;">Assigné à</td>
        <td style="padding:6px 0;color:#c9d1d9;">{assigned_display}</td>
      </tr>
      <tr style="border-top:1px solid #21262d;">
        <td style="padding:6px 0;color:#8b949e;">Verdict llama3</td>
        <td style="padding:6px 0;">
          {"<span style='color:#f85149;font-weight:700;'>✓ VRAI POSITIF</span>" if llm_verdict == "true_positive"
           else "<span style='color:#8b949e;'>✗ Faux positif</span>" if llm_verdict == "false_positive"
           else f"<span style='color:#8b949e;'>{llm_verdict}</span>"}
        </td>
      </tr>
      {f"""<tr style="border-top:1px solid #21262d;">
        <td style="padding:6px 0;color:#8b949e;">Intention de l'attaquant</td>
        <td style="padding:6px 0;color:#c9d1d9;font-style:italic;">"{attacker_intent}"</td>
      </tr>""" if attacker_intent else ""}
    </table>
  </div>

  <!-- RÉSUMÉ LLM -->
  {f'''<div style="background:#161b22;border-left:4px solid {color};border-radius:0 8px 8px 0;
                  padding:12px 16px;margin-bottom:16px;font-size:13px;color:#c9d1d9;
                  font-style:italic;">"{llm_summary}"</div>''' if llm_summary else ""}

  <!-- SCORES IA -->
  {scores_html}

  <!-- PREUVES -->
  {evidence_html}

  <!-- PLAYBOOK ACTIONS -->
  <div style="background:#161b22;border:1px solid {color}44;border-radius:10px;
              padding:16px 20px;margin-bottom:16px;">
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;
                color:{color};margin-bottom:14px;">
      {playbook['icon']} Actions immédiates — {playbook['title']}
      {f'<span style="margin-left:8px;color:#f85149;">⚠️ SLA DÉPASSÉ</span>' if sla_breached else
       f'<span style="margin-left:8px;color:#ffa657;">(SLA : {sla_remaining}min)</span>' if sla_remaining < 60 else ""}
    </div>
    {pb_steps_html}
  </div>

  {f"""<!-- ACTIONS LLM SPÉCIFIQUES -->
  <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
              padding:16px 20px;margin-bottom:16px;">
    <div style="font-size:10px;text-transform:uppercase;letter-spacing:2px;
                color:#d2a8ff;margin-bottom:10px;">Recommandations spécifiques (llama3)</div>
    <ul style="margin:0;padding-left:18px;">
      {"".join(f'<li style="font-size:12px;color:#c9d1d9;margin-bottom:6px;">{a}</li>' for a in llm_actions[:4])}
    </ul>
  </div>""" if llm_actions else ""}

  {f'<div style="background:#21262d;border-radius:8px;padding:10px 14px;margin-bottom:16px;font-size:12px;color:#c9d1d9;">ℹ️ {extra}</div>' if extra else ""}

  <!-- CTA -->
  <div style="text-align:center;margin-bottom:20px;">
    <a href="http://192.168.50.10:5000/incidents"
       style="display:inline-block;background:{color};color:#ffffff;padding:12px 32px;
              border-radius:8px;text-decoration:none;font-weight:700;font-size:14px;
              letter-spacing:0.5px;">
      Prendre en charge l'incident →
    </a>
  </div>

  <!-- FOOTER -->
  <div style="text-align:center;font-size:10px;color:#484f58;padding-top:16px;
              border-top:1px solid #21262d;">
    Mini-SOC · Système d'alerte automatique · {datetime.now().strftime("%Y-%m-%d %H:%M")}<br>
    Cet email a été généré automatiquement — ne pas répondre.
  </div>

</div>
</body></html>"""


# ─── ENVOI EMAIL ─────────────────────────────────────────────────────────────

def send_email(event_type, incident, extra=None, recipients=None):
    cfg  = load_config()
    ecfg = cfg.get("email", {})
    if not ecfg.get("enabled") or not ecfg.get("smtp_user"):
        return False

    # Destinataire unique : la personne concernée par l'incident
    to_email, recipient_user = get_recipient(incident)
    if recipients:
        # Override manuel (test, etc.)
        to_email = recipients[0] if recipients else None
        recipient_user = None
    if not to_email:
        log.warning("Aucun destinataire email trouvé pour cet incident")
        return False

    sev   = incident.get("severity", "medium")
    emoji = _SEV_EMOJI.get(sev, "⚪")
    ai    = incident.get("ai_analysis") or {}
    attack_type = (ai.get("attack_type") if isinstance(ai, dict) else None) or ""
    recipient_name = (recipient_user or {}).get("name", "") if recipient_user else ""
    subj = (f"{emoji} [{sev.upper()}] Incident assigné — "
            f"{attack_type or incident.get('title','Incident SOC')} — "
            f"{incident.get('incident_id','?')}")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subj
    msg["From"]    = ecfg.get("from_addr") or ecfg["smtp_user"]
    msg["To"]      = to_email

    html_body = _build_email_html(event_type, incident, extra, recipient_user=recipient_user)
    msg.attach(MIMEText(html_body, "html"))

    port     = int(ecfg.get("smtp_port", 587))
    use_ssl  = ecfg.get("use_ssl", False) or port == 465
    password = ecfg["smtp_pass"].replace(" ", "").strip()
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(ecfg["smtp_host"], port, timeout=15) as srv:
                srv.ehlo()
                srv.login(ecfg["smtp_user"], password)
                srv.sendmail(msg["From"], [to_email], msg.as_string())
        else:
            with smtplib.SMTP(ecfg["smtp_host"], port, timeout=15) as srv:
                srv.ehlo()
                srv.starttls()
                srv.login(ecfg["smtp_user"], password)
                srv.sendmail(msg["From"], [to_email], msg.as_string())
        log.info(f"Email [{event_type}] {incident.get('incident_id','?')} → {to_email} ({recipient_name})")
        return True
    except smtplib.SMTPAuthenticationError:
        log.error("Email auth failed — vérifier smtp_user/smtp_pass (App Password ?)")
        return False
    except Exception as e:
        log.error(f"Email error: {e}")
        return False


# ─── BROADCAST POST-EXPLOIT ───────────────────────────────────────────────────

def send_postexploit_alert(ip: str, technique: str, tactic: str, severity: str,
                            matched: str, timestamp: str, events: list) -> int:
    """
    Envoie un email à TOUS les utilisateurs actifs avec une vraie adresse email,
    tous niveaux confondus (L1 + L2 + L3), dès qu'un accès post-exploit est détecté.
    Retourne le nombre d'emails envoyés.
    """
    cfg  = load_config()
    ecfg = cfg.get("email", {})
    if not ecfg.get("enabled") or not ecfg.get("smtp_user"):
        return 0

    users = _load_users()
    recipients = [
        u.get("email", "").strip()
        for u in users.values()
        if u.get("active", True)
        and u.get("email", "").strip()
        and not u.get("email", "").endswith(".local")
    ]
    if not recipients:
        return 0

    sev_emoji   = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}.get(severity, "🔴")
    sev_color   = {"critical": "#f85149", "high": "#ffa657", "medium": "#e3b341", "low": "#8b949e"}.get(severity, "#f85149")
    tactic_name = tactic.split("—")[-1].strip() if "—" in tactic else tactic
    ts_short    = timestamp[:19].replace("T", " ")

    # Résumé des techniques détectées
    techniques_seen = list({e.get("technique","") for e in events if e.get("technique")})
    tech_list_html  = "".join(
        f'<li style="margin:3px 0;font-size:13px;color:#cdd9e5;">'
        f'<b style="color:{sev_color};">▸</b> {t.replace("_"," ").title()}</li>'
        for t in techniques_seen
    )

    html_body = f"""
    <div style="font-family:Arial,sans-serif;background:#0d1117;padding:24px;border-radius:10px;max-width:600px;margin:auto;">
      <div style="border-left:4px solid {sev_color};padding:0 0 0 16px;margin-bottom:20px;">
        <div style="font-size:22px;font-weight:700;color:#f0f6fc;">
          {sev_emoji} Post-Exploitation détectée
        </div>
        <div style="font-size:13px;color:#8b949e;margin-top:4px;">{ts_short} UTC</div>
      </div>

      <table style="width:100%;border-collapse:collapse;margin-bottom:20px;">
        <tr style="background:#161b22;"><td style="padding:10px 14px;color:#8b949e;font-size:12px;width:40%;border:1px solid #30363d;">IP Attaquante</td>
          <td style="padding:10px 14px;color:#58a6ff;font-family:monospace;font-size:14px;border:1px solid #30363d;"><b>{ip}</b></td></tr>
        <tr><td style="padding:10px 14px;color:#8b949e;font-size:12px;border:1px solid #30363d;">Tactique MITRE</td>
          <td style="padding:10px 14px;color:#f0f6fc;font-size:13px;border:1px solid #30363d;">{tactic_name}</td></tr>
        <tr style="background:#161b22;"><td style="padding:10px 14px;color:#8b949e;font-size:12px;border:1px solid #30363d;">Sévérité</td>
          <td style="padding:10px 14px;font-size:13px;border:1px solid #30363d;">
            <span style="background:{sev_color};color:#fff;padding:3px 10px;border-radius:4px;font-weight:700;text-transform:uppercase;font-size:11px;">{severity}</span>
          </td></tr>
        <tr><td style="padding:10px 14px;color:#8b949e;font-size:12px;border:1px solid #30363d;">Pattern détecté</td>
          <td style="padding:10px 14px;color:#ffa657;font-family:monospace;font-size:12px;border:1px solid #30363d;">{matched[:120]}</td></tr>
      </table>

      {'<div style="margin-bottom:18px;"><div style="font-size:12px;color:#8b949e;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;">Techniques détectées (' + str(len(techniques_seen)) + ')</div><ul style="list-style:none;padding:0;margin:0;background:#161b22;border-radius:6px;padding:12px;">' + tech_list_html + '</ul></div>' if techniques_seen else ''}

      <div style="background:#1c2128;border:1px solid #f8514933;border-radius:8px;padding:14px;margin-bottom:20px;">
        <div style="font-size:12px;color:#f85149;font-weight:700;margin-bottom:6px;">⚡ ACTION IMMÉDIATE REQUISE</div>
        <div style="font-size:13px;color:#cdd9e5;">Un accès non autorisé a été détecté sur votre infrastructure.
        Vérifiez la page <b>Post-Exploitation</b> du SOC pour les détails complets et le kill chain.</div>
      </div>

      <div style="text-align:center;margin-top:20px;">
        <a href="http://localhost:5000/postexploit" style="background:{sev_color};color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:700;font-size:14px;">
          🔍 Voir le Kill Chain
        </a>
      </div>

      <div style="margin-top:20px;font-size:11px;color:#484f58;text-align:center;border-top:1px solid #21262d;padding-top:12px;">
        Mini-SOC — Alerte automatique post-exploitation · Diffusé à tous les niveaux (L1/L2/L3)
      </div>
    </div>
    """

    sent = 0
    for to_email in set(recipients):
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"{sev_emoji} [POST-EXPLOIT {severity.upper()}] {tactic_name} — {ip}"
            msg["From"]    = ecfg.get("from_addr") or ecfg["smtp_user"]
            msg["To"]      = to_email
            msg.attach(MIMEText(html_body, "html", "utf-8"))

            _port = int(ecfg.get("smtp_port", 587))
            _ssl  = ecfg.get("use_ssl", False) or _port == 465
            _pwd  = ecfg["smtp_pass"].replace(" ", "").strip()
            if _ssl:
                with smtplib.SMTP_SSL(ecfg.get("smtp_host","smtp.gmail.com"), _port) as s:
                    s.ehlo(); s.login(ecfg["smtp_user"], _pwd)
                    s.sendmail(msg["From"], to_email, msg.as_string())
            else:
                with smtplib.SMTP(ecfg.get("smtp_host","smtp.gmail.com"), _port) as s:
                    s.ehlo(); s.starttls(); s.login(ecfg["smtp_user"], _pwd)
                    s.sendmail(msg["From"], to_email, msg.as_string())
            log.info(f"Post-exploit alert envoyé → {to_email}")
            sent += 1
        except Exception as e:
            log.warning(f"Échec envoi post-exploit alert → {to_email}: {e}")
    return sent


# ─── WEBHOOK (SLACK / DISCORD) ────────────────────────────────────────────────

def _build_slack_payload(event_type, incident, extra=None):
    sev   = incident.get("severity", "medium")
    color = _SEV_COLORS.get(sev, "#8b949e")
    emoji = _SEV_EMOJI.get(sev, "⚪")
    iid   = incident.get("incident_id", "—")
    title = incident.get("title", "Incident SOC")
    ip    = incident.get("src_ip", "—")
    score = incident.get("anomaly_score") or incident.get("unified_score") or "—"
    assigned = incident.get("assigned_to") or "Non assigné"
    ai = incident.get("ai_analysis") or {}
    if not isinstance(ai, dict):
        ai = {}
    attack_type = ai.get("attack_type") or ""
    summary     = ai.get("summary") or ""
    actions     = (ai.get("actions") or [])[:3]
    llm_verdict = incident.get("llm_verdict") or "—"
    created     = (incident.get("created_at") or "")[:16].replace("T", " ")
    sla_rem, sla_breached = _sla_remaining(incident)
    playbook = _get_playbook(attack_type)

    event_labels = {
        "new_incident": "Nouvel incident détecté",
        "assigned":     "Incident assigné",
        "escalated":    "⬆️ Incident escaladé",
        "sla_breach":   "⚠️ SLA dépassé",
    }
    sla_text = f"⚠️ DÉPASSÉ +{abs(sla_rem)}min" if sla_breached else f"{sla_rem}min restantes"

    blocks = [
        {"type": "header", "text": {"type": "plain_text",
            "text": f"{emoji} {playbook['icon']} {event_labels.get(event_type, event_type)}", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f"*{title}*\n`{iid}` · {created}"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*IP Attaquante*\n`{ip}`"},
            {"type": "mrkdwn", "text": f"*Type d'attaque*\n{playbook['icon']} {attack_type or '—'}"},
            {"type": "mrkdwn", "text": f"*Sévérité*\n{sev.upper()}"},
            {"type": "mrkdwn", "text": f"*Score IA*\n`{score}`"},
            {"type": "mrkdwn", "text": f"*Assigné à*\n{assigned}"},
            {"type": "mrkdwn", "text": f"*SLA*\n{sla_text}"},
        ]},
    ]
    if summary:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"_{summary}_"}})
    if actions:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": "📋 *Actions recommandées :*\n" + "\n".join(f"• {a}" for a in actions)}})
    if extra:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"ℹ️ {extra}"}})
    blocks.append({"type": "actions", "elements": [
        {"type": "button", "text": {"type": "plain_text", "text": "Prendre en charge →"},
         "url": "http://192.168.50.10:5000/incidents", "style": "primary"}
    ]})
    blocks.append({"type": "divider"})
    return {"attachments": [{"color": color, "blocks": blocks}]}


def _build_discord_payload(event_type, incident, extra=None):
    sev   = incident.get("severity", "medium")
    color_int = {"critical": 16335185, "high": 16737879, "medium": 14931777, "low": 4112848}.get(sev, 9211020)
    emoji = _SEV_EMOJI.get(sev, "⚪")
    iid   = incident.get("incident_id", "—")
    title = incident.get("title", "Incident SOC")
    ip    = incident.get("src_ip", "—")
    score = incident.get("anomaly_score") or incident.get("unified_score") or "—"
    assigned = incident.get("assigned_to") or "Non assigné"
    ai = incident.get("ai_analysis") or {}
    if not isinstance(ai, dict):
        ai = {}
    attack_type     = ai.get("attack_type") or ""
    summary         = ai.get("summary") or ""
    actions         = (ai.get("actions") or [])[:3]
    attacker_intent = ai.get("attacker_intent") or ""
    llm_verdict     = incident.get("llm_verdict") or "—"
    created         = (incident.get("created_at") or "")[:16].replace("T", " ")
    sla_rem, sla_breached = _sla_remaining(incident)
    playbook = _get_playbook(attack_type)
    geoip  = incident.get("geoip") or {}
    geo_str = f"{geoip.get('city','')}, {geoip.get('country','')}" if geoip.get("country") else ""

    event_labels = {
        "new_incident": "Nouvel incident détecté",
        "assigned":     "Incident assigné",
        "escalated":    "⬆️ Incident escaladé",
        "sla_breach":   "⚠️ SLA dépassé",
    }

    fields = [
        {"name": "IP Attaquante",    "value": f"`{ip}`{chr(10)+geo_str if geo_str else ''}", "inline": True},
        {"name": "Type d'attaque",   "value": f"{playbook['icon']} {attack_type or '—'}", "inline": True},
        {"name": "Sévérité",         "value": sev.upper(), "inline": True},
        {"name": "Score IA",         "value": str(score),  "inline": True},
        {"name": "Assigné à",        "value": assigned,    "inline": True},
        {"name": "SLA",              "value": f"⚠️ DÉPASSÉ" if sla_breached else f"{sla_rem}min", "inline": True},
    ]
    if attacker_intent:
        fields.append({"name": "Intention", "value": f'_{attacker_intent}_', "inline": False})
    if summary:
        fields.append({"name": "Résumé llama3", "value": summary[:200], "inline": False})
    if actions:
        fields.append({"name": "Actions recommandées",
                       "value": "\n".join(f"• {a}" for a in actions), "inline": False})
    if extra:
        fields.append({"name": "Info", "value": extra, "inline": False})

    return {"embeds": [{
        "title":       f"{emoji} {playbook['icon']} {event_labels.get(event_type, event_type)} — {iid}",
        "description": f"**{title}**",
        "color":       color_int,
        "fields":      fields,
        "footer":      {"text": f"Mini-SOC · {playbook['title']} · {created}"},
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "url":         "http://192.168.50.10:5000/incidents",
    }]}


def send_webhook(event_type, incident, extra=None):
    cfg  = load_config()
    wcfg = cfg.get("webhook", {})
    if not wcfg.get("enabled") or not wcfg.get("url"):
        return False

    wtype = wcfg.get("type", "slack")
    payload = _build_discord_payload(event_type, incident, extra) if wtype == "discord" \
              else _build_slack_payload(event_type, incident, extra)

    try:
        r = requests.post(wcfg["url"], json=payload, timeout=8)
        r.raise_for_status()
        log.info(f"Webhook [{event_type}] {incident.get('incident_id','?')} → HTTP {r.status_code}")
        return True
    except Exception as e:
        log.error(f"Webhook error: {e}")
        return False


# ─── DISPATCHER ──────────────────────────────────────────────────────────────

def notify(event_type, incident, extra=None, async_send=True):
    cfg = load_config()
    if not cfg.get("enabled"):
        return

    sev = incident.get("severity", "medium")
    if event_type == "new_incident" and sev not in cfg.get("notify_severities", ["critical", "high"]):
        return
    if event_type == "assigned"   and not cfg.get("notify_on_assign"):    return
    if event_type == "escalated"  and not cfg.get("notify_on_escalate"):  return
    if event_type == "sla_breach" and not cfg.get("notify_on_sla_breach"): return

    def _send():
        results = {}
        if cfg.get("email", {}).get("enabled"):
            results["email"]   = send_email(event_type, incident, extra)
        if cfg.get("webhook", {}).get("enabled"):
            results["webhook"] = send_webhook(event_type, incident, extra)
        log.info(f"Notify [{event_type}] {incident.get('incident_id','?')}: {results}")

    if async_send:
        threading.Thread(target=_send, daemon=True).start()
    else:
        _send()


def test_notifications():
    """Envoie une notification de test sur tous les canaux."""
    fake_incident = {
        "incident_id":   "INC-TEST-001",
        "title":         "SSH Brute Force — Test de notification",
        "severity":      "high",
        "src_ip":        "192.168.122.231",
        "anomaly_score": 0.847,
        "assigned_to":   "",
        "llm_verdict":   "true_positive",
        "votes":         4,
        "if_score":      0.72, "rf_score": 0.98, "dl_score": 0.45, "rate_count": 185,
        "created_at":    datetime.now(timezone.utc).isoformat(),
        "ai_analysis": {
            "attack_type":      "SSH Brute Force",
            "confidence":       0.94,
            "summary":          "Volume anormal de 185 tentatives SSH depuis 192.168.122.231 en 5 minutes.",
            "threat_level":     "haute",
            "attacker_intent":  "Obtenir un accès SSH root par force brute",
            "evidence":         [
                "185 tentatives SSH en 5 minutes (seuil : 10)",
                "4/4 modèles IA concordants",
                "Activité à 02h34 — hors heures normales",
                "IP non référencée dans les logs légitimes",
            ],
            "actions": [
                "Bloquer l'IP avec iptables immédiatement",
                "Vérifier les connexions SSH réussies depuis cette IP",
                "Activer fail2ban si pas déjà en place",
            ],
        },
    }
    results = {}
    cfg = load_config()
    if cfg.get("email", {}).get("enabled"):
        results["email"]   = send_email("new_incident", fake_incident, "Ceci est un test de notification.")
    if cfg.get("webhook", {}).get("enabled"):
        results["webhook"] = send_webhook("new_incident", fake_incident, "Ceci est un test de notification.")
    return results
