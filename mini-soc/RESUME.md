# Mini-SOC — Résumé Technique du Projet PFA 2025–2026

> **Plateforme** : Flask + Gunicorn · **ML** : Isolation Forest / Random Forest / Autoencoder / Rate Detector · **LLM** : Ollama llama3 + gemma2 · **RAG** : ChromaDB + nomic-embed-text · **SIEM** : Elasticsearch 8.x

---

## 1. Architecture Générale

```
┌─────────────────────────────────────────────────────────────┐
│                     Mini-SOC Platform                        │
│                                                              │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐  │
│  │ Isolation│   │  Random  │   │Autoencoder│   │  Rate   │  │
│  │  Forest  │   │  Forest  │   │   (DL)   │   │Detector │  │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬────┘  │
│       └──────────────┴──────────────┴───────────────┘       │
│                        Ensemble Detector                     │
│                     (vote pondéré ×4)                       │
│                              │                               │
│              ┌───────────────▼───────────────┐              │
│              │        Flask App (app.py)      │              │
│              │  157 routes · 34 templates     │              │
│              └───────────────┬───────────────┘              │
│                              │                               │
│   ┌──────────────────────────┼──────────────────────┐       │
│   │                          │                       │       │
│   ▼                          ▼                       ▼       │
│ Elasticsearch 8.x       Ollama LLM              ChromaDB     │
│ soc-incidents           llama3:8B               104 chunks   │
│ soc-logs*               gemma2:2b               nomic-embed  │
│ soc-anomalies           nomic-embed-text        RAG pipeline │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Stack Technique

| Composant | Technologie | Détail |
|-----------|-------------|--------|
| Backend | Flask 3.x + Gunicorn | 2 workers, port 5000 |
| SIEM | Elasticsearch 8.x | Indices : soc-incidents, soc-logs*, soc-anomalies, soc-rf-anomalies, soc-dl-anomalies |
| ML Détection | scikit-learn | Isolation Forest, Random Forest, Autoencoder (Keras), Rate Detector |
| LLM | Ollama | llama3:latest (4.4 GB), gemma2:2b (1.5 GB) |
| Embeddings | nomic-embed-text | 768 dimensions, via Ollama |
| RAG | ChromaDB 1.5.9 | 104 chunks, 7 PDFs SOC |
| PDF Generation | fpdf2 | Rapports incidents, playbooks |
| Auth | Session Flask + bcrypt + TOTP (pyotp) | RBAC L1/L2/L3 |
| Frontend | Bootstrap 5 + Chart.js 4 | Sidebar fixe droite, HTB palette |
| Infra | Kali Linux, Tailscale VPN | 3 VMs |

---

## 3. RBAC — Niveaux d'Accès (NIST CSF 2.0)

| Niveau | Rôle | Accès |
|--------|------|-------|
| **L1** | Analyste junior | Dashboard, Logs, Incidents (lecture), Investigation, Corrélation, Playbooks, Mesures, RAG |
| **L2** | Analyste senior | Tout L1 + Analytics, Ensemble IA, Ollama LLM, Post-Exploitation, CVE, Tailscale, Kibana, Threat Hunting, clôture incidents, actions de mitigation |
| **L3** | Admin / RSSI | Tout L2 + Gestion utilisateurs, Journal d'audit, Shifts SOC, Notifications, Réentraînement RF, Rebuild index RAG |

---

## 4. Détecteurs ML

### 4.1 Isolation Forest (IF) — Non supervisé
- Détecte les comportements rares et isolés dans les logs
- Seuil critique : score ≥ 0.85
- Avantage : fonctionne sans labels, détecte les nouvelles techniques
- Limite : faux positifs sur les opérations de maintenance

### 4.2 Random Forest (RF) — Supervisé
- Classifie sur la base des incidents précédents labelisés par les analystes
- Seuil : probabilité ≥ 0.65
- S'améliore avec le temps (feedback loop via labels L1/L2)
- Réentraînement via `/api/ollama/retrain_rf` (L3 uniquement)

### 4.3 Autoencoder DL — Deep Learning non supervisé
- Mesure l'erreur de reconstruction des séquences de logs
- Seuil : erreur normalisée ≥ 0.75
- Excellent pour détecter les séquences d'actions suspectes

### 4.4 Rate Detector — Volumétrique
- Compte les événements par IP par unité de temps
- Seuil : 10 événements/minute (configurable)
- Première ligne de défense, très rapide

### 4.5 Ensemble Detector — Vote pondéré
```
Score = 0.30 × IF + 0.35 × RF + 0.20 × DL + 0.15 × Rate
Incident créé si Score ≥ 0.28 ET votes ≥ 2 modèles
```

---

## 5. Système RAG (Retrieval Augmented Generation)

### Principe
Le RAG permet à llama3 de répondre aux questions SOC en se basant **uniquement** sur la documentation officielle, sans hallucination.

```
Question analyste
      │
      ▼
nomic-embed-text (vectorisation)
      │
      ▼
ChromaDB (recherche sémantique → top 4 chunks)
      │
      ▼
Prompt enrichi : contexte + question
      │
      ▼
llama3:latest (génération réponse)
      │
      ▼
Réponse + sources + scores de similarité
```

### Documents indexés (104 chunks)

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
| `/api/rag/query` | POST | L1+ | Question → réponse llama3 avec contexte |
| `/api/rag/search` | POST | L1+ | Recherche sémantique dans les chunks |
| `/api/rag/status` | GET | L1+ | Statut de la base vectorielle |
| `/api/rag/rebuild` | POST | L3 | Reconstruction complète de l'index |

---

## 6. SLA & Auto-Escalade

| Sévérité | SLA | Responsable |
|----------|-----|-------------|
| Critique | 4 heures | L2 + escalade L3 |
| Élevé | 8 heures | L2 |
| Moyen | 24 heures | L1/L2 |
| Faible | 72 heures | L1 |

**Auto-escalade** (thread daemon, toutes les 30 min) :
- Investigations en `new` depuis > 48h → sévérité augmentée + notification L2/L3
- Incidents dépassant le SLA → statut `breached` + notification L3

---

## 7. Enrichissement AbuseIPDB

- Cache 24h en mémoire pour éviter les appels redondants
- IPs privées (RFC 1918) ignorées automatiquement
- Affichage inline sur la page détail d'incident
- Bouton de chargement à la demande si non enrichi à la création

---

## 8. Corrélation d'Incidents

Page `/correlation` — regroupe les alertes par :
- **IP source** : historique complet, score de risque, incidents liés
- **Campagne** : groupes d'IPs ayant des patterns similaires
- **Heatmap 72h** : activité par heure sur 3 jours
- **Flyout IP** : détail timeline, sévérités, types d'attaque

---

## 9. Couverture MITRE ATT&CK (Enterprise v14)

| Tactique | Couverture |
|----------|-----------|
| Initial Access (T1110, T1190) | ✅ 75% |
| Lateral Movement (T1021.004, T1078) | ✅ 67% |
| Impact (T1498 DoS) | ✅ 50% |
| Privilege Escalation | ⚠️ 33% |
| Collection / Exfiltration | ⚠️ 17% |
| Reconnaissance | ❌ 0% |
| **Total** | **40% (8/27)** |

---

## 10. Pages de la Plateforme

| URL | Description | Niveau |
|-----|-------------|--------|
| `/` | Dashboard — score de risque global, KPIs, SLA | L1+ |
| `/incidents` | Liste des incidents avec badges SLA | L1+ |
| `/queue` | File de priorité des incidents | L1+ |
| `/logs` | Logs bruts en temps réel | L1+ |
| `/investigation` | Investigations ML avec scores par modèle | L1+ |
| `/correlation` | Corrélation IP / campagnes / heatmap | L1+ |
| `/playbooks` | Playbooks SOC (PDF viewer) | L1+ |
| `/mesures` | Mesures de sécurité actives | L1+ |
| `/rag` | Base de connaissances SOC — RAG llama3 | L1+ |
| `/analytics` | Graphiques analytiques avancés | L2+ |
| `/ensemble` | Détecteur ensemble — tableau de bord ML | L2+ |
| `/ollama` | Interface Ollama LLM | L2+ |
| `/postexploit` | Post-exploitation kill chain tracker | L2+ |
| `/cve` | CVE tracker avec CVSS | L2+ |
| `/tailscale` | Gestion VPN Tailscale | L2+ |
| `/hunting` | Threat Hunting | L2+ |
| `/kibana` | Dashboards Kibana | L2+ |
| `/admin/users` | Gestion des utilisateurs | L3 |
| `/admin/audit` | Journal d'audit complet | L3 |
| `/admin/shifts` | Gestion des shifts SOC | L3 |
| `/admin/notifications` | Configuration notifications | L3 |

---

## 11. Commandes Utiles

```bash
# Démarrer l'application
cd /opt/mini-soc
nohup venv/bin/gunicorn -w 2 -b 0.0.0.0:5000 app:app > /tmp/gunicorn.log 2>&1 &

# Vérifier Ollama
curl http://localhost:11434/api/tags

# Reconstruire l'index RAG
cd rag && ../venv/bin/python build_index.py

# Tester le RAG en CLI
cd rag && ../venv/bin/python rag_query.py "Quelles sont les étapes SSH brute force ?"

# Logs Gunicorn
tail -f /tmp/gunicorn.log

# Elasticsearch status
curl -u elastic:changeme http://localhost:9200/_cluster/health?pretty
```

---

## 12. Variables d'Environnement

| Variable | Description |
|----------|-------------|
| `FLASK_SECRET` | Clé secrète Flask (sessions) |
| `ABUSEIPDB_KEY` | Clé API AbuseIPDB pour enrichissement IP |
| `ES_HOST` | URL Elasticsearch (défaut: localhost:9200) |
| `ES_USER` | Utilisateur ES |
| `ES_PASSWORD` | Mot de passe ES |

---

*Dernière mise à jour : 2026-05-22 — Mini-SOC Platform v2.0 · PFA INPT*
