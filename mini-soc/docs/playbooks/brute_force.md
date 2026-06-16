# Playbook — Brute Force SSH (T1110)

## Objectif
Répondre à une attaque par force brute sur le service SSH.

## Indicateurs de compromission
- Nombre élevé de tentatives d'authentification échouées depuis une même IP
- Messages `Failed password` ou `Invalid user` dans `/var/log/auth.log`
- Score de détection Isolation Forest ou Random Forest > 0.7

## Étapes de réponse

### 1. Triage
- Vérifier le score composite et les votes des 4 modèles IA
- Confirmer que l'IP source n'est pas une adresse interne légitime
- Consulter la réputation AbuseIPDB de l'IP source

### 2. Containment
- Appliquer le blocage iptables via le bouton **Mitiger** (L2+)
- Vérifier que la règle est bien appliquée : `sudo iptables -L INPUT | grep <ip>`

### 3. Eradication
- Vérifier les comptes potentiellement compromis : `lastb | grep <ip>`
- Réinitialiser les mots de passe des comptes ciblés
- Vérifier si fail2ban est actif : `systemctl status fail2ban`
- Si absent, activer fail2ban ou configurer `MaxAuthTries` dans sshd_config

### 4. Recovery
- Vérifier que le service SSH est toujours opérationnel pour les utilisateurs légitimes
- Contrôler les connexions actives : `who` et `w`

### 5. Lessons Learned
- Documenter l'IP, la période d'attaque et le nombre de tentatives
- Enregistrer dans le rapport post-incident (bouton **Générer rapport PDF**)

## Références MITRE ATT&CK
- T1110 — Brute Force
- T1110.001 — Password Guessing
- T1110.004 — Credential Stuffing
