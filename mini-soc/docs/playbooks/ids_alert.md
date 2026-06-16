# Playbook — Alerte IDS / Suricata (TA0001 → TA0011)

## Objectif
Traiter une alerte générée par Suricata ou un autre IDS intégré au pipeline.

## Indicateurs de compromission
- Règle Suricata déclenchée (signature en clair dans le log)
- Trafic réseau anormal détecté (port scan, payload suspect)
- Événement indexé dans `soc-logs` avec `log_type: syslog` ou `log_type: suricata`

## Étapes de réponse

### 1. Triage
- Lire la règle Suricata déclenchée dans le détail des logs
- Vérifier le trafic associé : IP source, port destination, protocole
- Identifier si l'alerte est un vrai positif (TP) ou un faux positif (FP)

### 2. Containment
- Si TP confirmé : isoler le host si un accès physique est possible
- Bloquer l'IP source via **Mitiger** si l'attaque vient de l'extérieur
- Capturer le trafic pour analyse forensique : `sudo tcpdump -i eth0 host <ip> -w /tmp/capture.pcap`

### 3. Eradication
- Analyser la charge utile capturée
- Vérifier les connexions actives : `ss -tupan | grep <ip>`
- Arrêter tout processus suspect : `ps aux | grep <pid>`

### 4. Recovery
- Redémarrer les services impactés si nécessaire
- Vérifier les règles Suricata et les mettre à jour si la signature est obsolète

### 5. Lessons Learned
- Si FP : valider comme False Positive dans la plateforme → amélioration automatique du modèle IA
- Si TP : générer le rapport post-incident

## Références MITRE ATT&CK
- TA0001 — Initial Access
- T1046 — Network Service Scanning
- T1071 — Application Layer Protocol (C&C)
