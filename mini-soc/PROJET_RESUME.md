# Mini-SOC PFA — Résumé Complet du Projet

> **Projet** : Mini Security Operations Center (SOC) — PFA  
> **Stack** : Flask · Elasticsearch · Logstash · Filebeat · Ollama llama3 · Python ML  
> **Équipe** : Admin SOC (L3), Analyste L2, Analyste L1  
> **Date** : Mai 2026

---

## 1. Architecture Générale

### Infrastructure 3 VMs
| Machine | Rôle | IP |
|---|---|---|
| **Kali Linux** (hôte) | SOC — Flask, ELK, Ollama | 192.168.122.1 (virbr0) |
| **VM cible** | arthur@arthur-Standard-PC | 192.168.122.104 |
| **Elasticsearch** | Base de données SOC | localhost:9200 |

### Pipeline de données
```
VM cible (Filebeat) → SSH tunnel :5044 → Logstash (Kali) → Elasticsearch → Flask SOC
```

---

## 2. Modules Python (Détecteurs)

| Fichier | Rôle | Statut |
|---|---|---|
| `ia_detector.py` | Isolation Forest — détection d'anomalies | ✅ Actif |
| `dl_detector.py` | Autoencoder Deep Learning (Keras) | ✅ Actif |
| `rf_detector.py` | Random Forest supervisé | ✅ Actif |
| `ensemble_detector.py` | Méta-learner fusionnant IF+DL+RF | ✅ Actif |
| `meta_learner.py` | Score de confiance combiné | ✅ Actif |
| `postexploit_detector.py` | Détection MITRE ATT&CK post-exploitation | ✅ Actif |
| `llm_analyzer.py` | Triage automatique Ollama llama3 | ✅ Actif |
| `rate_detector.py` | Détection par taux (brute-force SSH) | ✅ Actif |
| `cve_scanner.py` | Scan CVE et indexation soc-cve-alerts | ✅ Actif |
| `auto_labeler.py` | Labellisation automatique TP/FP | ✅ Actif |
| `auto_retrain.py` | Ré-entraînement automatique du modèle RF | ✅ Actif |
| `notifier.py` | Notifications email SMTP (Gmail App Password) | ✅ Actif |

---

## 3. Indices Elasticsearch (état actuel)

| Index | Docs | Contenu |
|---|---|---|
| `soc-incidents` | 71 | Incidents ML détectés (68 in_progress, 3 closed) |
| `soc-anomalies` | 41 877 | Anomalies Isolation Forest |
| `soc-dl-anomalies` | 170 155 | Anomalies Autoencoder DL |
| `soc-rf-anomalies` | 73 | Anomalies Random Forest |
| `soc-postexploit-events` | 16 | Événements MITRE ATT&CK post-exploit |
| `soc-notifications` | 58 | Notifications email envoyées |
| `soc-audit-log` | 134 | Actions admin tracées (login, config, etc.) |
| `soc-cve-alerts` | 24 | Alertes CVE (CVSS ≥ 7.0) |
| `soc-anomaly-labels` | 82 | Labels TP/FP humains (feedback loop) |
| `soc-blocked-ips` | 1 | IPs bloquées via iptables DROP |
| `soc-logs-*` | — | Logs bruts SSH/auth (Filebeat → Logstash) |

---

## 4. Application Flask (app.py ~4 700 lignes)

### Authentification & RBAC
- **3 niveaux** : L1 (analyste), L2 (senior), L3 (admin)
- Sessions Flask signées + audit log complet
- Décorateurs `@require_auth`, `@require_level("L2")`, `@require_level("L3")`
- Comptes actifs : admin (L3), analyst_l2 (L2), analyst_l1 (L1)

### Pages principales
| Route | Accès | Description |
|---|---|---|
| `/` | L1+ | Dashboard principal |
| `/incidents` | L1+ | Liste incidents ML |
| `/incident/<id>` | L1+ | Détail + triage + verdict Ollama |
| `/logs` | L1+ | Logs Elasticsearch bruts |
| `/analytics` | L2+ | Analytique avancée |
| `/ia` | L2+ | Isolation Forest |
| `/dl` | L2+ | Autoencoder DL |
| `/compare` | L2+ | Comparaison pipelines ML |
| `/pipeline` | L2+ | Vue pipeline complet |
| `/cve` | L1+ | CVE alerts |
| `/mesures` | L1+ | Métriques SOC |
| `/postexploit` | L2+ | Kill chain MITRE ATT&CK + NIST CSF |
| `/ollama` | L2+ | Interface LLM directe |
| `/kibana` | L3 | Iframe Kibana |
| `/admin/users` | L3 | Gestion comptes utilisateurs |
| `/admin/notifications` | L3 | Gestion notifications |
| `/audit_log` | L3 | Journal d'audit |
| `/playbooks` | L2+ | Playbooks de réponse |
| `/report` | L2+ | Génération de rapports |

### APIs principales
| Endpoint | Description |
|---|---|
| `GET /api/postexploit/nist_coverage` | Scores NIST CSF dynamiques depuis ES |
| `GET /api/postexploit/latest` | Dernier événement PE (polling bot) |
| `GET /api/postexploit/ip_incidents/<ip>` | Incidents liés à une IP |
| `GET /api/postexploit/ip_logs/<ip>` | Logs liés à une IP |
| `GET /api/postexploit/sessions` | Sessions SSH actives |
| `POST /api/bot/chat` | Chat SOC Bot (Ollama streaming SSE) |
| `POST /api/incidents/<id>/mitigate` | Blocage iptables + soc-blocked-ips |
| `POST /api/incidents/<id>/analyze` | Analyse Ollama llama3 |
| `POST /api/incidents/<id>/report` | Rapport post-incident |
| `POST /admin/users/<u>/delete` | Suppression utilisateur (L3) |
| `POST /admin/users/<u>/toggle` | Activation/désactivation compte |
| `POST /admin/users/<u>/reset_password` | Reset mot de passe |
| `GET /api/nist_coverage` | Score NIST CSF global |

---

## 5. Détection Post-Exploitation MITRE ATT&CK

### Tactiques détectées (postexploit_detector.py)
| Code | Tactique | Patterns détectés |
|---|---|---|
| TA0001 | Initial Access | SSH connexion depuis IP externe |
| TA0002 | Execution | `bash -i`, `python3 -c`, `nc`, pipes |
| TA0003 | Persistence | `crontab`, `~/.bashrc`, `/etc/cron.d` |
| TA0004 | Privilege Escalation | `sudo`, `USER=root`, `su root` |
| TA0005 | Defense Evasion | `rm -rf /var/log`, `history -c`, `unset HIST` |
| TA0006 | Credential Access | `/etc/shadow`, `.ssh/id_rsa`, `cat /etc/passwd` |
| TA0007 | Discovery | `whoami`, `id`, `uname -a`, `ifconfig` |
| TA0008 | Lateral Movement | `ssh <ip>` depuis la cible |
| TA0010 | Exfiltration | `scp`, `wget`, `curl`, `nc` |
| TA0011 | C2 | Connexions sortantes sur ports non-standards |

### Sévérité automatique
- **CRITICAL** : Privilege Escalation, Persistence, Defense Evasion
- **HIGH** : Credential Access, Lateral Movement, C2
- **MEDIUM** : Discovery, Execution
- **LOW** : Initial Access seul

### Actions automatiques lors de détection
1. Création d'incident dans `soc-incidents`
2. Envoi email à **tous les niveaux** L1+L2+L3
3. Alerte SOC Bot (popup + badge)
4. Indexation dans `soc-postexploit-events`

---

## 6. SOC Bot (base.html)

### Interface
- **Bouton flottant** en bas à droite avec visage robot animé (CSS pur)
- Badge rouge avec nombre d'alertes non lues
- Panel slide-up 400px avec historique de chat

### Fonctionnalités
- **Alertes automatiques** : polling toutes les 30s sur `/api/postexploit/latest`
- **Chat conversationnel** : Ollama llama3 avec contexte SOC temps réel
- **Streaming SSE** : tokens affichés en temps réel (heartbeat `: ping` toutes les 5s)
- **Actions rapides** : boutons contextuels (bloquer IP, voir incident)
- **Rendu Markdown** dans les réponses du bot
- **Déduplication** des alertes via `localStorage` (`pe_last_seen`)

### Contexte injecté dans chaque requête bot
- Incidents ouverts/critiques
- Anomalies 24h
- Événements PE 24h
- IPs bloquées
- 2 derniers PE events
- 2 derniers incidents ouverts

---

## 7. Notifications Email (notifier.py)

### Déclencheurs
| Événement | Destinataires |
|---|---|
| Post-exploitation détectée | Tous (L1+L2+L3) actifs avec email réel |
| Incident critique créé | L2+L3 |
| Incident assigné | L1 concerné |

### Destinataires actifs
| Utilisateur | Niveau | Email |
|---|---|---|
| admin | L3 | admin@example.com |
| analyst_l2 | L2 | analyst.l2@example.com |
| analyst_l1 | L1 | analyst.l1@example.com |

### Format email post-exploit
- Badge sévérité coloré
- Tableau IP / Tactique / Technique
- Pattern détecté (matched)
- Bouton "Voir le Kill Chain"
- Section ACTION REQUIRED

---

## 8. NIST CSF — Scores actuels (dynamiques)

| Fonction | Score | Items |
|---|---|---|
| **ID — Identify** | **95%** | AM 80% · RA 100% · RA2 100% · GV 100% |
| **PR — Protect** | **85%** | AC 100% · DS 80% · MA 60% · IP 100% |
| **DE — Detect** | **100%** | AE 100% · CM 100% · DP 100% · ML 100% |
| **RS — Respond** | **100%** | RP 100% · CO 100% · AN 100% · MI 100% · IM 100% |
| **RC — Recover** | **93%** | RP 80% · IM 100% · CO 100% |
| **Score global** | **94%** | |

Tous les scores sont calculés **dynamiquement** depuis Elasticsearch à chaque chargement de la page `/postexploit`.

---

## 9. Gestion des Utilisateurs (admin)

- Création compte (username, nom, niveau L1/L2/L3, email, mot de passe bcrypt)
- Activation / Désactivation
- Reset mot de passe
- **Suppression** avec confirmation + animation fade
- Modification email (pour notifications)
- Affichage rôle et statut

---

## 10. Attaques réalisées (lab)

Kill chain complète exécutée sur la VM cible (192.168.122.104) :

```
Initial Access (SSH) → Execution (bash) → Discovery (whoami/uname/netstat)
→ Privilege Escalation (sudo su) → Persistence (crontab/bashrc)
→ Credential Access (shadow/passwd) → Defense Evasion (history clear)
→ Exfiltration (curl/scp) → C2 (reverse shell nc)
```

Toutes les étapes détectées et indexées dans `soc-postexploit-events`.

---

## 11. Infrastructure de Collecte de Logs

### Sur la VM cible
- **Filebeat** configuré → `output.logstash.hosts: ["127.0.0.1:5044"]`
- Collecte : `/var/log/auth.log`, `/var/log/syslog`, journald
- Transmission via **SSH remote port forwarding** → tunnel vers Kali :5044

### Sur Kali (SOC)
- **Logstash** écoute sur `:5044`
- Pipeline : parse grok → enrichissement → output ES `soc-logs-*`
- **Elasticsearch** 8.x sur `localhost:9200`
- **Ollama** llama3 (8B, Q4_0) sur `localhost:11434` (CPU-only)

---

*Généré le 2026-05-17 — Mini-SOC PFA*
