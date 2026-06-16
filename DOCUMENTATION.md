# Mini-SOC PFA — Documentation Complète (All In All)

> **Projet** : Mini Security Operations Center — PFA 2025–2026  
> **Équipe** : Admin SOC (L3) · Analyste L2 (Senior) · Analyste L1  
> **Stack** : Flask · Elasticsearch 8.x · Ollama (llama3 + gemma2 + nomic-embed-text) · ChromaDB RAG · Python ML  
> **Dernière mise à jour** : 05 Juin 2026

---

## Table des matières

1. [Vue d'ensemble du projet](#1-vue-densemble-du-projet)
2. [Infrastructure — 3 VMs](#2-infrastructure--3-vms)
3. [Stack technique complète](#3-stack-technique-complète)
4. [Architecture générale](#4-architecture-générale)
5. [Détecteurs ML — 4 modèles](#5-détecteurs-ml--4-modèles)
6. [Système RAG (ChromaDB + llama3)](#6-système-rag-chromadb--llama3)
7. [Application Flask — Pages & Routes](#7-application-flask--pages--routes)
8. [RBAC — Niveaux d'accès (NIST CSF 2.0)](#8-rbac--niveaux-daccès-nist-csf-20)
9. [Fonctionnalités avancées](#9-fonctionnalités-avancées)
10. [SOC Bot & LLM](#10-soc-bot--llm)
11. [Notifications & SOAR](#11-notifications--soar)
12. [Couverture NIST CSF 2.0](#12-couverture-nist-csf-20)
13. [Couverture MITRE ATT&CK](#13-couverture-mitre-attck)
14. [Interface utilisateur (Sidebar fixe)](#14-interface-utilisateur-sidebar-fixe)
15. [Déploiement Docker](#15-déploiement-docker)
16. [Sécurité & Hardening](#16-sécurité--hardening)
17. [Attaques simulées en lab](#17-attaques-simulées-en-lab)
18. [Architecture — Recommandations & Perspectives](#18-architecture--recommandations--perspectives)
19. [Commandes utiles](#19-commandes-utiles)
20. [Fichiers clés du projet](#20-fichiers-clés-du-projet)
21. [Historique des améliorations majeures](#21-historique-des-améliorations-majeures)

---

## 1. Vue d'ensemble du projet

Le **Mini-SOC** est une plateforme complète de Security Operations Center développée dans le cadre du PFA (Projet de Fin d'Année). Il s'agit d'un système de détection et de réponse aux incidents qui combine :

- Un **SIEM** basé sur Elasticsearch + Kibana
- **4 modèles de Machine Learning** en détection parallèle
- Un **LLM local** (llama3) pour l'analyse automatique des incidents
- Un système **RAG** (Retrieval Augmented Generation) pour la base de connaissances SOC
- Une **application Flask** avec 157 routes, 34 templates, RBAC 3 niveaux
- Un déploiement **Docker Compose** clé en main

**URL de production** : `http://192.168.50.10:5000`  
**Credentials par défaut** : `admin` / `ChangeMe123!` (L3 — à changer en production)

---

## 2. Infrastructure — 3 VMs

| Machine | Rôle | IP | OS |
|---------|------|----|----|
| **Kali Linux** (hôte) | SOC — Flask, ELK, Ollama, ChromaDB | 192.168.122.1 / 192.168.50.10 (Tailscale) | Kali Linux |
| **VM cible** | Serveur victime (SSH, Apache) | 192.168.122.104 | Ubuntu (arthur-Standard-PC) |
| **VM attaquant** | Génération d'attaques (optionnel) | 192.168.122.x | Kali |

**Réseau** : Tailscale VPN mesh entre les 3 VMs — les VMs ne communiquent pas directement sur le réseau local.

**Pipeline de données** :
```
VM cible (Filebeat) → SSH tunnel :5044 → Logstash (Kali) → Elasticsearch → Flask SOC
```

---

## 3. Stack technique complète

| Composant | Technologie | Détail |
|-----------|-------------|--------|
| Backend | Flask 3.x + Gunicorn | 2 workers, port 5000, timeout 120s |
| SIEM | Elasticsearch 8.19 | 11 indices soc-* |
| Dashboards | Kibana 8.x | Port 5601, SSO automatique |
| ML Détection | scikit-learn + Keras | IF, RF, Autoencoder, Rate Detector |
| LLM | Ollama | llama3:latest (4.4 GB), gemma2:2b (1.5 GB) |
| Embeddings | nomic-embed-text | 768 dimensions, via Ollama |
| RAG | ChromaDB 1.5.9 | 104 chunks, 7 PDFs SOC |
| Base vectorielle | PersistentClient | `rag/vectors/`, collection `soc_knowledge` |
| PDF Generation | fpdf2 | Rapports incidents |
| Auth | Session Flask + bcrypt + TOTP (pyotp) | RBAC L1/L2/L3 |
| Rate Limiting | Flask-Limiter | 5 req/min sur /login |
| Frontend | Bootstrap 5 + Chart.js 4 | Sidebar fixe droite, palette HTB |
| Chiffrement | cryptography.fernet | AES-128 symétrique |
| VPN | Tailscale | Réseau mesh 3 VMs |
| Déploiement | Docker Compose | 6 services + 4 volumes |

**Palette HTB (Hack The Box) utilisée dans l'UI** :
```css
--bg:     #111927   /* fond principal */
--cyan:   #00D9FF   /* accent principal */
--red:    #FF4757   /* alertes critiques */
--orange: #FF6B35   /* warnings */
--green:  #9FEF00   /* statuts OK */
--yellow: #FFD700   /* sévérité haute */
--purple: #A78BFA   /* ML / IA */
```

---

## 4. Architecture générale

```
┌─────────────────────────────────────────────────────────────────┐
│                       Mini-SOC Platform                          │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌─────────────┐   │
│  │Isolation │  │ Random   │  │Autoencoder│  │    Rate     │   │
│  │ Forest   │  │ Forest   │  │   (DL)    │  │  Detector   │   │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘  └──────┬──────┘   │
│       └─────────────┴──────────────┴────────────────┘           │
│                      Ensemble Detector                           │
│               (IF×30% + RF×35% + DL×20% + Rate×15%)            │
│               Vote minimum : ≥ 2/4 modèles · Seuil : 0.28      │
│                              │                                   │
│              ┌───────────────▼───────────────┐                  │
│              │       Flask App (app.py)       │                  │
│              │   157 routes · 34 templates    │                  │
│              └───────────────┬───────────────┘                  │
│                              │                                   │
│   ┌──────────────────────────┼──────────────────────┐           │
│   │                          │                       │           │
│   ▼                          ▼                       ▼           │
│ Elasticsearch 8.x        Ollama LLM             ChromaDB         │
│ soc-incidents            llama3:8B              104 chunks       │
│ soc-logs-*               gemma2:2b              nomic-embed      │
│ soc-anomalies            nomic-embed-text       RAG pipeline     │
│ soc-rf-anomalies                                                  │
│ soc-dl-anomalies                                                  │
│ soc-postexploit-events                                            │
│ soc-audit-log                                                     │
│ soc-blocked-ips                                                   │
│ soc-cve-alerts                                                    │
│ soc-notifications                                                 │
│ soc-anomaly-labels                                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Détecteurs ML — 4 modèles

### 5.1 Isolation Forest (IF) — Non supervisé
- **Principe** : détecte les comportements rares et isolés dans les logs
- **Seuil critique** : score ≥ 0.85
- **Score moyen observé** : 0.541
- **Avantage** : fonctionne sans labels, détecte les nouvelles techniques (zero-day)
- **Limite** : faux positifs sur les opérations de maintenance
- **Index ES** : `soc-anomalies`

### 5.2 Random Forest (RF) — Supervisé
- **Principe** : classifie sur la base des incidents précédents labellisés par les analystes
- **Résultats** : F1=1.000 / Precision=1.000 / Recall=1.000 sur dataset test
- **Seuil** : probabilité ≥ 0.65
- **Features** : `is_failed`, `is_invalid_usr`, `is_sshd_auth`, `has_src_ip`, `is_session_ok`, `hour_of_day`, `is_night`, `is_web_attack`
- **S'améliore avec le temps** via boucle feedback Ollama → labels → retrain auto (≥ 3 nouveaux labels)
- **Index ES** : `soc-rf-anomalies`

### 5.3 Autoencoder DL — Deep Learning non supervisé
- **Principe** : mesure l'erreur de reconstruction des séquences de logs (MSE)
- **Seuil** : erreur normalisée ≥ 0.75 — MSE observé : 0.886
- **Excellent** pour détecter les séquences d'actions jamais vues
- **Boucle DL** : exclut les IPs TP de la baseline normale, enrichit avec logs FP validés Ollama
- **Index ES** : `soc-dl-anomalies`

### 5.4 Rate Detector — Volumétrique
- **Principe** : compte les événements par IP par unité de temps
- **Seuil SSH** : 30 tentatives/minute
- **Première ligne de défense**, très rapide, très faible coût CPU
- **Cas d'usage** : brute force SSH, flood web

### 5.5 Ensemble Detector — Vote pondéré
```
Score = 0.30 × IF  +  0.35 × RF  +  0.20 × DL  +  0.15 × Rate

Conditions de création d'incident :
  → Score ≥ 0.28  ET  votes ≥ 2 modèles sur 4
```
- **Index ES** : `soc-ensemble-anomalies`
- **Auto-assign** : critical/high → L2, medium → L1 (least-loaded analyst)

### 5.6 Post-Exploit Detector — MITRE ATT&CK
- **Fichier** : `postexploit_detector.py`
- Détecte 10 tactiques MITRE en temps réel
- Actions automatiques : création incident + email + bot alert + analyse SOAR
- **Index ES** : `soc-postexploit-events`

### 5.7 Auto-Labeler & Retrain
- `auto_labeler.py` : labellise automatiquement TP/FP via Ollama (confiance ≥ 75%)
- `auto_retrain.py` : ré-entraîne le RF automatiquement si ≥ 3 nouveaux labels
- **Boucle complète** : Ollama → labels → RF retrain → DL baseline update

### 5.8 Dataset d'entraînement
- 8 245 logs total : 3 463 attaques, 4 782 normaux
- 3 IPs attaque découvertes par Ollama : `192.168.122.1`, `192.168.122.231`, `10.0.0.100`
- Labels dynamiques : IPs connues + verdicts LLM (TP/FP validés)

---

## 6. Système RAG (ChromaDB + llama3)

### Principe
Le RAG permet à llama3 de répondre aux questions SOC en se basant **uniquement** sur la documentation officielle, sans hallucination.

```
Question analyste
      │
      ▼
nomic-embed-text (vectorisation 768D)
      │
      ▼
ChromaDB (recherche sémantique → top 4 chunks)
      │
      ▼
Prompt enrichi : contexte documentaire + question
      │
      ▼
llama3:latest (génération réponse)
      │
      ▼
Réponse + sources + scores de similarité
```

### Configuration technique
- **ChromaDB** : PersistentClient, répertoire `rag/vectors/`, collection `soc_knowledge`
- **Embeddings** : nomic-embed-text via Ollama (768 dimensions)
- **Chunking** : 500 caractères, overlap 80
- **Top-K** : 4 chunks par requête
- **Version** : ChromaDB 1.5.9

### Documents indexés (104 chunks, 7 PDFs)

| Document | Référence | Chunks |
|----------|-----------|--------|
| Playbook SSH Brute Force | PB-SSH-001 | 20 |
| Playbook Web Attack (SQLi/XSS/LFI) | PB-WEB-002 | 20 |
| Playbook CVE & Patch Management | PB-CVE-003 | 14 |
| Procédure NIST CSF 2.0 | PROC-NIST-004 | 10 |
| Politique de Réponse aux Incidents | POL-IR-005 | 8 |
| Matrice MITRE ATT&CK Enterprise v14 | REF-ATT-006 | 9 |
| Playbook Investigation Anomalie IA | PB-IA-007 | 23 |

### API RAG

| Endpoint | Méthode | Niveau | Description |
|----------|---------|--------|-------------|
| `/rag` | GET | L1+ | Page interface RAG |
| `/api/rag/query` | POST | L1+ | Question → réponse llama3 avec contexte |
| `/api/rag/search` | POST | L1+ | Recherche sémantique dans les chunks |
| `/api/rag/status` | GET | L1+ | Statut de la base vectorielle (104 chunks) |
| `/api/rag/rebuild` | POST | L3 | Reconstruction complète de l'index |

### UI RAG (`rag.html`)
- Suggestions rapides (questions fréquentes SOC)
- Affichage de la réponse + sources avec scores de similarité
- Barre de score visuelle par chunk
- Bouton rebuild index (L3 uniquement)
- `Ctrl+Enter` pour envoyer

---

## 7. Application Flask — Pages & Routes

### Pages L1+ (tous les analystes)

| URL | Description |
|-----|-------------|
| `/` | Dashboard — score de risque global, KPIs, SLA, statut services |
| `/incidents` | Liste incidents — pagination server-side, filtres, bulk triage |
| `/incident/<id>` | Détail incident + triage + verdict Ollama + export PDF |
| `/queue` | File de priorité des incidents |
| `/logs` | Logs Elasticsearch bruts en temps réel |
| `/investigation` | Investigations ML avec scores par modèle |
| `/correlation` | Corrélation IP / campagnes / heatmap 72h |
| `/playbooks` | Playbooks SOC (PDF viewer) |
| `/mesures` | Mesures de sécurité actives + commandes iptables |
| `/rag` | Base de connaissances SOC — RAG llama3 |
| `/cve` | CVE alerts avec CVSS ≥ 7.0 + liens NVD |
| `/profile` | Profil utilisateur + changement mdp + setup TOTP |

### Pages L2+ (analystes seniors)

| URL | Description |
|-----|-------------|
| `/analytics` | Graphiques analytiques avancés + dérive de modèle |
| `/ia` | Isolation Forest — anomalies détaillées |
| `/dl` | Autoencoder DL — anomalies |
| `/ensemble` | Détecteur ensemble — tableau de bord ML |
| `/compare` | Comparaison IF vs RF |
| `/pipeline` | Vue pipeline complet — statut temps réel |
| `/ollama` | Interface Ollama LLM directe |
| `/postexploit` | Kill chain MITRE + risk scores par IP + timeline |
| `/hunting` | Threat Hunting — éditeur ES JSON + 7 presets + export CSV |
| `/tailscale` | Gestion VPN Tailscale |
| `/kibana` | Dashboards Kibana + SSO automatique |
| `/report` | Génération de rapports |

### Pages L3 (admin / RSSI)

| URL | Description |
|-----|-------------|
| `/admin/users` | Gestion des comptes utilisateurs |
| `/admin/audit` | Journal d'audit complet (toutes actions tracées) |
| `/admin/shifts` | Gestion des shifts SOC |
| `/admin/notifications` | Configuration notifications email |

### APIs principales

| Endpoint | Description |
|----------|-------------|
| `GET /api/home/services` | État de tous les services (ELK, ML, Filebeat health) |
| `GET /api/shifts` | Liste des shifts + shift actif |
| `POST /api/shifts/<name>/assign` | Assigner/retirer un analyste |
| `GET /api/postexploit/risk_scores` | Score de risque dynamique 0-100 par IP |
| `GET /api/timeline/<ip>` | Timeline interactive d'une IP (5 sources agrégées) |
| `POST /api/hunting/query` | Requête ES libre (L2+) |
| `POST /api/incidents/bulk_action` | Bulk triage (max 100 IDs) |
| `GET /api/incidents/<id>/report/pdf` | Export PDF fpdf2 |
| `POST /api/incidents/<id>/analyze` | Analyse Ollama + verdict JSON |
| `POST /api/incidents/<id>/mitigate` | Blocage iptables + soc-blocked-ips (L2+) |
| `POST /api/bot/chat` | Chat SOC Bot (gemma2:2b streaming SSE) |
| `GET /kibana-sso` | Authentification SSO Kibana + redirect |
| `POST /api/ollama/retrain_rf` | Ré-entraînement RF depuis interface (L3) |
| `GET /api/model_drift` | Dérive de modèle IF sur 14 jours |
| `GET /api/postexploit/nist_coverage` | Scores NIST CSF dynamiques |

---

## 8. RBAC — Niveaux d'accès (NIST CSF 2.0)

| Niveau | Rôle | Accès |
|--------|------|-------|
| **L1** | Analyste junior | Dashboard, Logs, Incidents (lecture + triage basique), Investigation, Corrélation, Playbooks, Mesures, RAG, CVE, Profil |
| **L2** | Analyste senior | Tout L1 + Analytics, Ensemble IA, Ollama LLM, Post-Exploitation, Tailscale, Kibana, Threat Hunting, Clôture incidents, Blocage IP iptables, Rapports |
| **L3** | Admin / RSSI | Tout L2 + Gestion utilisateurs, Journal d'audit, Shifts SOC, Notifications, Réentraînement RF, Rebuild index RAG, Fernet key gen |

**Implémentation** :
- Décorateurs `@require_auth` et `@require_level("L2")`
- `@app.context_processor` injecte `current_user` dans tous les templates
- Sessions Flask signées (bcrypt) + TOTP optionnel (pyotp)
- Audit trail complet dans `soc-audit-log` : login, logout, mfa_fail, incident_update, mitigate, etc.

**Comptes par défaut** :

| Username | Niveau | Nom |
|----------|--------|-----|
| `admin` | L3 | Admin SOC |
| `analyst_l2` | L2 | Analyste L2 |
| `analyst_l1` | L1 | Analyste L1 |

---

## 9. Fonctionnalités avancées

### Pagination server-side (/incidents)
- Paramètres : `?page=1&size=25&severity=critical&status=open&verdict=TP&q=192.168`
- Requêtes ES avec `from/size` — ne charge pas tout en mémoire
- Barre de pagination avec numéros de pages

### Bulk Triage
- Checkboxes sur chaque incident + "select all"
- Toolbar apparaît dès qu'une case est cochée
- Actions : Mettre en cours / Awaiting action / Clôturer / Assigner
- API `POST /api/incidents/bulk_action` (max 100 IDs)

### Export PDF (fpdf2)
- `GET /api/incidents/<id>/report/pdf`
- Header SOC, détails incident, rapport Ollama, métadonnées
- Bouton "Télécharger PDF" dans la page détail incident

### Threat Hunting (/hunting)
- Éditeur de requêtes ES JSON (textarea monospace)
- Sélecteur d'index (soc-logs-*, soc-anomalies, soc-incidents…)
- 7 presets : `brute_force`, `critical_logs`, `new_ips`, `failed_auth`, `pe_lateral`, `high_score`, `all_recent`
- Résultats en tableau avec colonnes auto-détectées
- Export CSV des résultats

### Timeline interactive par IP
- `GET /api/timeline/<ip>` agrège 5 sources (logs, anomalies, PE, incidents, blocages)
- Ligne de temps avec points colorés par type d'événement
- Clic sur une IP dans le tableau risk scores → timeline s'affiche

### Risk Score par IP (0-100)
- PE events : +40 pts (CRITICAL) / +25 pts (HIGH)
- Anomalies ML : +15 pts
- Incidents : +20 pts (critical) / +10 pts (high)
- Blocage actif : badge rouge
- Tableau dans /postexploit avec barre de progression colorée

### Gestion des Shifts SOC (/admin/shifts)
- 3 shifts par défaut : Matin (06h-14h), Après-midi (14h-22h), Nuit (22h-06h)
- Détection automatique du shift actif par l'heure courante
- Assignation d'analystes à un shift (pills avec × pour retirer)
- Indicateur dans la sidebar : nom du shift actif + nb de membres
- Création de shifts personnalisés (nom, couleur, icône, horaires)
- Données persistées dans `shifts.json`

### SOAR Auto-Response
- `soar_auto_analyze()` déclenché automatiquement sur incidents critical/high
- Thread background : analyse gemma2:2b → résumé SOAR indexé dans l'incident
- Déclenché à la création d'incident ET à chaque run LLM

### Kibana SSO
- `/kibana-sso` : POST vers `/internal/security/login` de Kibana, forward du cookie `sid`
- Tous les liens Kibana passent par ce proxy
- Status badge Kibana (version, up/down) dans la page /kibana

### Fernet Encryption
- `encrypt_field()` / `decrypt_field()` — AES-128 symétrique
- `POST /api/admin/generate_fernet_key` — génère une clé (L3)
- Stocker en `FERNET_KEY` dans `.env`

### Filebeat Health Check
- Widget "Filebeat" dans le dashboard : compte les logs reçus dans les 5 dernières minutes
- Label dynamique : "Filebeat (X logs/5min)" — vert si >0, rouge si silence

### SLA & Auto-Escalade
| Sévérité | SLA | Responsable |
|----------|-----|-------------|
| Critique | 4 heures | L2 + escalade L3 |
| Élevé | 8 heures | L2 |
| Moyen | 24 heures | L1/L2 |
| Faible | 72 heures | L1 |

Thread daemon (toutes les 30 min) :
- Investigations `new` depuis > 48h → sévérité augmentée + notification L2/L3
- Incidents dépassant le SLA → statut `breached` + notification L3

### Enrichissement AbuseIPDB
- Cache 24h en mémoire pour éviter les appels redondants
- IPs privées (RFC 1918) ignorées automatiquement
- Affichage inline sur la page détail d'incident

### GeoIP
- ip-api.com + cache mémoire
- Enrichissement des incidents avec pays de l'IP attaquante

### Dérive de modèle
- `/api/model_drift` + panel analytics sur 14 jours
- Score moyen IF tracé dans le temps pour détecter une montée de faux positifs

---

## 10. SOC Bot & LLM

### SOC Bot (gemma2:2b)
- Bouton flottant en bas à gauche — visage robot animé CSS
- Badge rouge avec nombre d'alertes non lues
- **Streaming SSE** : tokens gemma2:2b affichés en temps réel (~20s sur CPU)
- **Alertes automatiques** : polling 30s sur `/api/postexploit/latest`
- **Contexte temps réel** injecté : incidents ouverts, anomalies 24h, IPs bloquées, PE events
- Rendu Markdown dans les réponses
- Modèle : gemma2:2b (1.6 GB, ~20s CPU) — léger et rapide

### Modèles Ollama

| Modèle | Taille | Usage | Temps CPU |
|--------|--------|-------|-----------|
| `gemma2:2b` | 1.6 GB | Bot SOC + SOAR auto-response | ~20s |
| `llama3:latest` | 4.4 GB | Génération rapports + RAG | ~2-3 min |
| `nomic-embed-text` | 274 MB | Embeddings RAG (768D) | rapide |

### Analyse Ollama llama3
- Analyse structurée JSON : `verdict`, `attack_type`, `confidence`, `evidence`, `actions`
- Few-shot memory : exemples haute confiance (conf ≥ 0.80) mémorisés dans `llm_memory.json`
- Sémaphore threading : 1 seul appel LLM à la fois (évite les timeouts concurrents)
- Timeout 240s (llama3 sur CPU prend ~170-200s), fallback automatique
- `OLLAMA_URL` en variable d'environnement (remplace tous les hardcoded localhost:11434)

---

## 11. Notifications & SOAR

### Déclencheurs email
| Événement | Destinataires |
|-----------|---------------|
| Post-exploitation détectée | Tous (L1+L2+L3) avec email actif |
| Incident critique créé | L2+L3 |
| Incident assigné | L1 concerné |

### Destinataires
| Utilisateur | Niveau | Email |
|-------------|--------|-------|
| admin | L3 | admin@example.com |
| analyst_l2 | L2 | analyst.l2@example.com |
| analyst_l1 | L1 | analyst.l1@example.com |

### Webhook
- `SOC_WEBHOOK_URL` (variable d'environnement)
- Déclenché sur incidents critiques
- Compatible Slack / Discord / ntfy

---

## 12. Couverture NIST CSF 2.0

### Scores après implémentation complète

```
GOVERN   [█████████░]  88%  Politique sécu, audit trail ES, playbooks, revues
IDENTIFY [████████░░]  85%  pip-audit, SBOM, inventaire données, GeoIP
PROTECT  [█████████░]  88%  bcrypt, Limiter, session 8h, MFA TOTP, chmod 600
DETECT   [█████████░]  96%  4 modèles ML, GeoIP, dérive de modèle — POINT FORT
RESPOND  [█████████░]  90%  Webhook, playbooks, mitigation auto iptables
RECOVER  [████████░░]  80%  Backup cron, procédure reprise, lessons learned

GLOBAL   [█████████░]  88%  Tier 3 (Repeatable) — éléments Tier 4 sur DETECT
```

### Tier NIST atteint : **Tier 3 — Repeatable**
Ce qui a permis la progression Tier 2 → Tier 3 :
- Procédures formalisées (politique, playbooks, procédure reprise, inventaire données)
- Backup automatisé (`backup_soc.sh` + crontab 3h AM)
- Alertes externes (webhook critique + audit trail complet)
- Protections renforcées (bcrypt, rate limiting, MFA TOTP, session lifetime)
- Réponse automatisée (mitigation iptables depuis l'interface)
- Amélioration continue (dérive de modèle, lessons learned, retrain automatique RF)

### Mapping RBAC ↔ NIST CSF 2.0

| Niveau | Fonctions NIST |
|--------|----------------|
| L1 | ID (Identify) + DE (Detect) |
| L2 | PR (Protect) + RS (Respond) + RC (Recover) |
| L3 | GV (Govern) — supervision globale |

---

## 13. Couverture MITRE ATT&CK

### Techniques détectées

| Code | Tactique | Détecteur | Sévérité |
|------|----------|-----------|----------|
| TA0001 | Initial Access (SSH T1110) | Rate + RF | LOW |
| TA0002 | Execution | PE Detector | MEDIUM |
| TA0003 | Persistence (T1053 crontab) | PE Detector | CRITICAL |
| TA0004 | Privilege Escalation (T1068 sudo) | PE Detector | CRITICAL |
| TA0005 | Defense Evasion (history clear) | PE Detector | CRITICAL |
| TA0006 | Credential Access (shadow/passwd) | PE Detector | HIGH |
| TA0007 | Discovery (whoami/uname/netstat) | PE Detector | MEDIUM |
| TA0008 | Lateral Movement (SSH T1021.004) | RF + Ensemble | HIGH |
| TA0010 | Exfiltration (curl/scp T1048) | PE Detector | HIGH |
| TA0011 | C2 (reverse shell nc T1059) | PE Detector | HIGH |

### Couverture Enterprise v14

| Tactique | Couverture |
|----------|------------|
| Initial Access (T1110, T1190) | ✅ 75% |
| Lateral Movement (T1021.004, T1078) | ✅ 67% |
| Impact (T1498 DoS) | ✅ 50% |
| Privilege Escalation | ⚠️ 33% |
| Collection / Exfiltration | ⚠️ 17% |
| Reconnaissance | ❌ 0% |
| **Total** | **~40% (8/27 techniques)** |

---

## 14. Interface utilisateur (Sidebar fixe)

### Structure layout (base.html)
```
<body>
  <div class="app-layout">          ← flex, row-reverse, 100vw × 100vh
    <nav class="sidebar">           ← fixe à droite (flex-shrink: 0)
      ...nav items...
    </nav>
    <div class="main-wrapper">      ← flex: 1, overflow-y: auto
      <div class="page-content">
        {% block content %}
      </div>
      <footer>...</footer>
    </div>
  </div>
</body>
```

### CSS clé
```css
html, body { height: 100% !important; overflow: hidden !important; }
.app-layout { display: flex !important; flex-direction: row-reverse !important;
              width: 100vw !important; height: 100vh !important; overflow: hidden !important; }
.sidebar    { width: var(--sidebar-w) !important; flex-shrink: 0 !important;
              height: 100% !important; display: flex !important; flex-direction: column !important; }
.main-wrapper { flex: 1 1 0% !important; min-width: 0 !important;
                height: 100% !important; overflow-y: auto !important; }
```

### Navigation sidebar — Structure

**Section principale (L1+)** :
Accueil · Incidents · File de priorité · Logs · Investigation · Corrélation · Playbooks · Mesures · Base SOC RAG

**Section Avancé L2+** :
Analytics · Ensemble IA · Ollama LLM · Post-Exploit

**Section Outils L2+** :
CVE · Tailscale · Threat Hunting · Kibana · Kibana Discover

**Footer sidebar** : indicateur shift actif + pulse live + user pill + accordion admin (L3)

### Historique des bugs résolus (sidebar)
1. `backdrop-filter: blur()` sur sidebar créait un stacking context → brisait `position: fixed` sous Chromium → supprimé
2. `<script>` entre `</nav>` et `<div class="main-wrapper">` étaient des flex items → déplacés à l'intérieur de `.main-wrapper`
3. Body scroll non bloqué → JS enforcement ajouté : `document.body.style.cssText += ';overflow:hidden!important'`
4. Résolution finale : flex layout complet (pas de `position: fixed`) + JS enforcement au démarrage

---

## 15. Déploiement Docker

### Services (docker-compose.yml)

| Service | Image | Port | Rôle |
|---------|-------|------|------|
| `elasticsearch` | elasticsearch:8.12.2 | 9200 | SIEM |
| `kibana` | kibana:8.12.2 | 5601 | Dashboards |
| `ollama` | ollama/ollama:latest | 11434 | LLM local |
| `ollama-init` | ollama/ollama:latest | — | Pull modèles (one-shot) |
| `mini-soc` | build local (Dockerfile) | 5000 | Flask app |
| `rag-init` | build local (Dockerfile) | — | Build index ChromaDB (one-shot) |

### Volumes persistants

| Volume | Contenu |
|--------|---------|
| `es_data` | Données Elasticsearch (indices, logs) |
| `ollama_data` | Modèles Ollama (llama3, gemma2, nomic-embed) |
| `rag_vectors` | Base vectorielle ChromaDB (104 chunks) |
| `soc_users` | Fichier users.json (comptes analystes) |

### Ordre de démarrage
```
elasticsearch (healthy) → kibana
                       → ollama (healthy) → ollama-init (pull models)
                                          → mini-soc (healthy) → rag-init (build index)
```

### Dockerfile
```dockerfile
FROM python:3.11-slim
RUN apt-get install -y poppler-utils curl   # pdftotext pour RAG
COPY requirements.txt . && pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--timeout", "120", "app:app"]
```

### Variables d'environnement (.env)

| Variable | Valeur par défaut |
|----------|-------------------|
| `ES_HOST` | http://elasticsearch:9200 |
| `ES_USER` | elastic |
| `ES_PASSWORD` | changeme |
| `OLLAMA_URL` | http://ollama:11434 |
| `FLASK_SECRET` | mini-soc-secret-change-en-prod |
| `ABUSEIPDB_KEY` | (optionnel) |

### Commandes Docker
```bash
# Démarrage complet
docker compose up -d

# Suivre les logs
docker compose logs -f

# Premier démarrage : ~10-15 min (téléchargement des modèles Ollama)

# Accéder au shell de l'app
docker exec -it soc-app /bin/bash

# Reconstruire index RAG
docker exec -it soc-app /bin/sh -c "cd rag && python build_index.py"

# Tester Ollama
docker exec -it soc-ollama ollama list

# Arrêter (données conservées)
docker compose down

# Arrêter et supprimer tout
docker compose down -v
```

### Présentation PowerPoint (generate_pptx.py)
- Script python-pptx générant 14 slides
- Thème HTB dark avec toute la palette de couleurs
- Questions jury deep-dive incluses
- Output : `PFA_MiniSOC_Presentation.pptx`
- Helpers : `add_slide()`, `box()`, `txt()`, `tag()`, `kpi()`, `bullet_block()`, `accent_bar()`

---

## 16. Sécurité & Hardening

### Améliorations sécurité réalisées
- ✅ bcrypt pour le hashage des mots de passe (remplace SHA256)
- ✅ Flask-Limiter : 5 req/min sur POST `/login` (anti-brute force)
- ✅ Session expiration 8h (`permanent_session_lifetime`)
- ✅ MFA TOTP (pyotp) — `/profile/setup_totp`, QR code, vérification, désactivation
- ✅ Secret Flask en variable d'environnement
- ✅ `chmod 600` sur fichiers sensibles (users.json, modèles ML)
- ✅ Audit trail complet ES `soc-audit-log` (toutes actions tracées)
- ✅ Webhook alertes incidents critiques (`SOC_WEBHOOK_URL`)
- ✅ Backup quotidien ES + modèles (`backup_soc.sh`, crontab 3h AM)
- ✅ `pip-audit` — 7 CVE corrigées, 0 restantes (urllib3 → 2.7.0)
- ✅ `requirements_frozen.txt` (SBOM)
- ✅ Fernet encryption (AES-128) pour champs sensibles
- ✅ Mitigation automatique iptables DROP via l'interface (L2+)

### Ce qui reste pour production
- ⬜ TLS nginx devant Flask (config prête dans `docs/config/nginx_soc.conf`)
- ⬜ Chiffrement au repos Elasticsearch (`xpack.security.encryption`)
- ⬜ Service systemd pour les détecteurs (restart automatique)

### Note de sécurité critique
> Le Gmail App Password SMTP précédent `rnfl dudr tfte pgkk` est **RÉVOQUÉ et invalide**.  
> Ne jamais écrire les credentials en clair dans le terminal, le chat, ou le code.  
> Utiliser `.env` exclusivement.

---

## 17. Attaques simulées en lab

### Kill chain complète exécutée
```
Initial Access (SSH brute force)
→ Execution (bash commands)
→ Discovery (whoami / uname -a / netstat / ps aux)
→ Privilege Escalation (sudo su)
→ Persistence (crontab backdoor / .bashrc)
→ Credential Access (/etc/shadow + /etc/passwd → 50 comptes)
→ Defense Evasion (history -c)
→ Exfiltration (curl/scp)
→ C2 (reverse shell nc)
```

Toutes les étapes détectées et indexées dans `soc-postexploit-events`.

### Statistiques attaques générées
- 468+ tentatives SSH brute force (simulate_attack.sh × 2 boucles)
- 94 chemins web scannés (Nikto, LFI, .env, admin)
- 222 répertoires énumérés (DirBuster style)
- 20 payloads SQLi (sqlmap style)
- Post-exploitation réussie : connexion SSH dans VM victime

### Credentials VM cible utilisés en lab
- `attacker:changeme@192.168.50.30`

---

## 18. Architecture — Recommandations & Perspectives

### Ce qui est solide (ne pas changer)
- Détection ML à 4 modèles — rare même dans les SOC commerciaux
- LLM + RAG local — innovant, pas de dépendance cloud
- RBAC NIST mappé — professionnel
- Docker Compose — déploiement simple

### Ce qui manque et apporte une vraie valeur

**Priorité 1 — Filebeat (recommandé)**
- Installer Filebeat sur les VMs cibles
- Logs réels SSH / auth.log / nginx → vrais pipelines de détection
- Configuration : `filebeat.inputs` → output Elasticsearch direct (sans Logstash)
- Valeur jury : démo avec de vraies attaques sur de vrais logs

**Priorité 2 — ES Ingest Pipelines (au lieu de Logstash)**
- Logstash : NON — trop lourd, un service de plus, peu de valeur ajoutée
- ES Ingest Pipelines : OUI — parsing Grok intégré dans Elasticsearch, zéro infrastructure supplémentaire

### Sur Active Directory / OpenLDAP

```
Dans un vrai SOC, l'AD est ce qu'on SURVEILLE, pas ce qu'on CONSTRUIT.
```

| Rôle | Qui le fait |
|------|-------------|
| Infrastructure IT (AD, LDAP) | Sysadmin |
| SOC | Surveille l'infra, détecte les attaques |

**Usage cohérent** : OpenLDAP comme **infrastructure cible** (VM cible) → le SOC surveille et détecte les attaques LDAP (T1087 Account Discovery, T1110 Brute Force LDAP).

**Usage incohérent** : OpenLDAP pour l'authentification du SOC lui-même → confusion des rôles, complexité inutile.

### Ce qu'il ne faut PAS ajouter maintenant
- Logstash (ES Ingest Pipelines suffit)
- Kafka (surcharge pour un lab)
- PKI / certificats internes (hors scope)
- FreeIPA / Active Directory pour l'auth SOC (over-engineering)

---

## 19. Commandes utiles

### Démarrer la plateforme (sans Docker)
```bash
cd mini-soc

# Elasticsearch (systemd)
sudo systemctl start elasticsearch

# Ollama
OLLAMA_HOST=0.0.0.0 nohup ollama serve > /tmp/ollama.log 2>&1 &

# Flask (Gunicorn)
source venv/bin/activate
nohup gunicorn -w 2 -b 0.0.0.0:5000 --timeout 120 --log-level info app:app \
  > /tmp/gunicorn.log 2>&1 &

# Détecteurs ML (optionnel — peuvent tourner séparément)
nohup python3 ia_detector.py        > /tmp/ia.log 2>&1 &
nohup python3 dl_detector.py        > /tmp/dl.log 2>&1 &
nohup python3 rf_detector.py        > /tmp/rf.log 2>&1 &
nohup python3 rate_detector.py      > /tmp/rate.log 2>&1 &
nohup python3 ensemble_detector.py  > /tmp/ensemble.log 2>&1 &
nohup python3 postexploit_detector.py > /tmp/pe.log 2>&1 &
```

### Arrêter la plateforme
```bash
fuser -k 5000/tcp         # tuer Flask
pkill -f "ollama serve"   # tuer Ollama
sudo systemctl stop elasticsearch
```

### Vérifier l'état
```bash
# Flask
curl -sf http://localhost:5000/ -o /dev/null -w "%{http_code}"

# Elasticsearch
curl -u elastic:changeme http://localhost:9200/_cluster/health?pretty

# Ollama
curl http://localhost:11434/api/tags

# Logs Flask
tail -f /tmp/gunicorn.log
```

### RAG
```bash
# Reconstruire l'index
cd mini-soc/rag
../venv/bin/python build_index.py

# Tester une requête RAG en CLI
../venv/bin/python rag_query.py "Quelles sont les étapes SSH brute force ?"
```

### Créer le ZIP du projet
```bash
cd ~/project-pfa
zip -r project-pfa.zip project-pfa/ \
  --exclude "project-pfa/mini-soc/venv/*" \
  --exclude "project-pfa/mini-soc/__pycache__/*" \
  --exclude "project-pfa/mini-soc/rag/vectors/*"
```

---

## 20. Fichiers clés du projet

| Fichier | Description |
|---------|-------------|
| `app.py` | Application Flask principale (~5 500 lignes, 157 routes) |
| `config.py` | Credentials ES, clés Flask, config email |
| `.env` | Variables d'environnement (ES_HOST, OLLAMA_URL, FERNET_KEY…) |
| `users.json` | Comptes utilisateurs (bcrypt) |
| `shifts.json` | Configuration et historique des shifts SOC |
| `llm_memory.json` | Mémoire few-shot Ollama (analyses haute confiance) |
| `ia_detector.py` | Isolation Forest — détection anomalies non supervisée |
| `dl_detector.py` | Autoencoder Deep Learning (Keras) |
| `rf_detector.py` | Random Forest supervisé |
| `ensemble_detector.py` | Méta-learner fusionnant IF+DL+RF+Rate |
| `postexploit_detector.py` | Détection MITRE ATT&CK post-exploitation |
| `llm_analyzer.py` | Triage automatique Ollama llama3 |
| `rate_detector.py` | Détection par taux (brute-force SSH) |
| `cve_scanner.py` | Scan CVE NVD API + indexation soc-cve-alerts |
| `auto_labeler.py` | Labellisation automatique TP/FP via Ollama |
| `auto_retrain.py` | Ré-entraînement automatique du modèle RF |
| `notifier.py` | Notifications email SMTP (Gmail App Password) |
| `rag/build_index.py` | Construction de l'index ChromaDB depuis les PDFs |
| `rag/rag_query.py` | Requête RAG : embed → search → generate |
| `templates/base.html` | Layout global + sidebar fixe droite + SOC Bot |
| `templates/incidents.html` | Liste incidents + pagination + bulk triage |
| `templates/incident_detail.html` | Détail + export PDF + rapport Ollama |
| `templates/hunting.html` | Threat Hunting — éditeur ES + 7 presets |
| `templates/postexploit.html` | Kill chain + NIST + risk scores + timeline |
| `templates/rag.html` | Interface RAG — questions + réponses + sources |
| `templates/admin_shifts.html` | Gestion des shifts SOC (L3) |
| `docker-compose.yml` | 6 services + 4 volumes + healthchecks |
| `Dockerfile` | Image Flask (python:3.11-slim + poppler-utils) |
| `generate_pptx.py` | Génération présentation PowerPoint 14 slides |
| `backup_soc.sh` | Backup quotidien ES + modèles ML (crontab 3h AM) |
| `simulate_attack.py` | Simulation d'attaques pour le lab |

---

## 21. Historique des améliorations majeures

### Phase 1 — Infrastructure de base
- Mise en place Elasticsearch 8.x + Kibana
- Pipeline Filebeat → Logstash → ES
- Flask app avec routes basiques
- Premier modèle IF (Isolation Forest)

### Phase 2 — ML & LLM
- Ajout Random Forest supervisé (F1=1.000)
- Ajout Autoencoder Deep Learning (Keras)
- Intégration Ollama llama3 pour analyse automatique
- Ensemble detector (vote pondéré 4 modèles)
- Boucle feedback : Ollama → labels → RF retrain

### Phase 3 — Fonctionnalités SOC avancées
- RBAC L1/L2/L3 avec audit trail ES
- MFA TOTP (pyotp)
- Post-exploit detector MITRE ATT&CK
- Threat Hunting avec éditeur ES + presets
- Timeline interactive par IP
- Risk scores dynamiques
- Gestion des shifts SOC
- Kibana SSO
- Bulk triage incidents
- Export PDF rapports

### Phase 4 — Sécurité & NIST CSF 2.0
- bcrypt (remplace SHA256)
- Flask-Limiter anti-brute force
- Session expiration 8h
- Backup automatisé (crontab)
- Procédure de reprise documentée
- Politique de sécurité formelle
- Inventaire données RGPD
- pip-audit (0 CVE restantes)
- Fernet encryption

### Phase 5 — RAG & Déploiement
- ChromaDB 1.5.9 + nomic-embed-text
- Indexation 7 PDFs → 104 chunks
- Interface RAG (rag.html)
- Routes API RAG complètes
- Variable OLLAMA_URL (remplace tous les hardcoded)
- Context processor `current_user` (fix L2+ boutons sidebar)
- Docker Compose 6 services clé en main
- Dockerfile production (python:3.11-slim)
- PowerPoint 14 slides (python-pptx, thème HTB)
- ZIP déploiement équipe (project-pfa.zip, 172 MB)

### Phase 6 — Sidebar fixe (résolution bug complexe)
Le fix de la sidebar a nécessité 3 itérations :
1. Suppression `backdrop-filter: blur()` (brisait `position:fixed` sous Chromium)
2. Switch vers architecture flex layout (`row-reverse`) sans `position: fixed`
3. Déplacement des `<script>` à l'intérieur de `.main-wrapper` + JS enforcement `overflow: hidden`

---

*Document — Mini-SOC PFA v2.0*
