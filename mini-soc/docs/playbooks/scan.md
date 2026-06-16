# Playbook — Scan réseau / Reconnaissance (T1595 / T1046)

## Objectif
Répondre à une activité de reconnaissance réseau (scan de ports, scan web, fingerprinting).

## Indicateurs de compromission
- Nombreuses requêtes vers des ports fermés ou inattendus
- Séquence de requêtes HTTP vers des chemins non existants (404 répétés)
- Connexions TCP SYN sans suite (scan SYN) détectées par Suricata
- IP inconnue apparaissant pour la première fois dans les logs

## Étapes de réponse

### 1. Triage
- Identifier le type de scan : scan de ports, scan web, scan de vulnérabilités
- Vérifier si le scan est interne (audit légitime) ou externe (attaquant)
- Consulter la réputation AbuseIPDB de l'IP source
- Analyser la temporalité : le scan précède-t-il une tentative d'exploitation ?

### 2. Décision
- **Scan interne connu** : documenter comme FP, valider dans la plateforme
- **Scan externe suspect** : passer en mode Containment

### 3. Containment
- Bloquer l'IP malveillante via **Mitiger** (L2+)
- Vérifier si d'autres IPs similaires ont effectué des scans (page Corrélation → Campagnes)

### 4. Eradication
- Auditer les ports ouverts sur le système cible : `sudo ss -tlnp` ou `sudo nmap localhost`
- Fermer les ports inutiles : désactiver les services non essentiels
- Vérifier les règles de pare-feu : `sudo iptables -L`

### 5. Recovery
- S'assurer que les services légitimes ne sont pas impactés par les nouvelles règles
- Documenter les ports ouverts légitimes pour la baseline

### 6. Lessons Learned
- Mettre à jour la cartographie des services exposés
- Générer le rapport post-incident si le scan a précédé une attaque

## Références MITRE ATT&CK
- T1595 — Active Scanning
- T1595.001 — Scanning IP Blocks
- T1595.002 — Vulnerability Scanning
- T1046 — Network Service Discovery
