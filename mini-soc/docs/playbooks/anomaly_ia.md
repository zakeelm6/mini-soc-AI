# Playbook — Anomalie détectée par IA (Isolation Forest / Ensemble)

## Objectif
Investiguer une anomalie comportementale remontée par les modèles de machine learning.

## Indicateurs de compromission
- Score Isolation Forest ou Ensemble > 0.6
- Comportement inhabituel par rapport à la baseline (heure, fréquence, type de requête)
- Alerte sans signature connue (comportement nouveau, pas de règle Suricata)

## Étapes de réponse

### 1. Triage
- Examiner les **scores individuels** des 4 modèles (IF, RF, DL, Rate) dans la fiche incident
- Comparer le comportement avec l'historique de l'IP source (page Corrélation)
- Lancer l'**analyse Ollama** pour obtenir un verdict IA et des preuves

### 2. Investigation
- Corréler avec les logs bruts : chercher des patterns dans les 24h précédentes
- Utiliser la page **Threat Hunting** avec le preset `high_score` pour explorer les anomalies similaires
- Vérifier la réputation de l'IP sur AbuseIPDB (affiché dans la fiche incident)
- Si le score est > 8 : **escalader vers L3**

### 3. Décision TP/FP
- TP confirmé → passer à la phase Containment
- FP confirmé → valider comme False Positive dans la plateforme (améliore le modèle RF)
- Incertain → escalader vers L2 ou L3 pour décision

### 4. Containment (si TP)
- Bloquer l'IP via **Mitiger**
- Analyser si d'autres machines du réseau présentent des anomalies similaires

### 5. Lessons Learned
- Le feedback TP/FP améliore automatiquement le Random Forest et l'Autoencoder
- Documenter le type d'anomalie pour enrichir la base RAG

## Références MITRE ATT&CK
- T1078 — Valid Accounts (comportement légitime détourné)
- T1036 — Masquerading
