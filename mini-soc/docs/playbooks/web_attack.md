# Playbook — Attaque Web / Apache (T1190)

## Objectif
Répondre à une attaque ciblant l'application web (injection, scan, exploitation CVE).

## Indicateurs de compromission
- Codes HTTP 400/403/404/500 répétés depuis une même IP
- Requêtes vers des chemins suspects (`/admin`, `/.env`, `/wp-login.php`, `../../../`)
- CVE active détectée sur le service Apache par le CVE Scanner

## Étapes de réponse

### 1. Triage
- Analyser les requêtes HTTP dans les logs liés à l'incident
- Identifier la nature de l'attaque (scan, injection SQL, path traversal, CVE)
- Vérifier la CVE associée et son score CVSS

### 2. Containment
- Bloquer l'IP source via **Mitiger** (L2+)
- Si WAF disponible, ajouter une règle de blocage au niveau applicatif

### 3. Eradication
- Vérifier les fichiers uploadés récemment : `find /var/www -newer /tmp -type f`
- Scanner les vulnérabilités : `nikto -h localhost`
- Appliquer le patch ou workaround pour la CVE identifiée

### 4. Recovery
- Redémarrer Apache si nécessaire : `sudo systemctl restart apache2`
- Vérifier l'intégrité des fichiers web critiques

### 5. Lessons Learned
- Documenter la CVE, la version vulnérable et le patch appliqué
- Générer le rapport post-incident

## Références MITRE ATT&CK
- T1190 — Exploit Public-Facing Application
- T1059.007 — JavaScript/Web Shell
- T1505.003 — Web Shell
