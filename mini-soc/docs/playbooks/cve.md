# Playbook — CVE / Vulnérabilité critique (T1190 / T1203)

## Objectif
Répondre à la détection d'une CVE active sur un service exposé.

## Indicateurs de compromission
- CVE détectée par le CVE Scanner (indexée dans `soc-cve-alerts`)
- Score CVSS ≥ 7.0 → boost de sévérité automatique sur les incidents liés
- Service vulnérable exposé sur le réseau (SSH, Apache, OpenSSL…)

## Étapes de réponse

### 1. Triage
- Identifier la CVE, son score CVSS et le service affecté
- Vérifier si des incidents sont actifs liés à ce service/IP
- Évaluer l'exposition : le service est-il accessible depuis Internet ?

### 2. Identification des systèmes exposés
- Lister tous les hôtes exécutant le service vulnérable
- Scanner la version du service : `ssh -V`, `apache2 -v`, `openssl version`
- Comparer avec la version minimale corrigée indiquée dans la CVE

### 3. Mitigation immédiate
- Appliquer le **workaround** si le patch n'est pas encore disponible (désactiver la fonctionnalité vulnérable, filtrer par IP)
- Si exploitation active détectée : bloquer l'IP source via **Mitiger**

### 4. Patching
- Appliquer le patch de sécurité : `sudo apt update && sudo apt upgrade <paquet>`
- Vérifier la version après mise à jour
- Redémarrer le service si nécessaire

### 5. Vérification
- Scanner à nouveau les hôtes pour confirmer que la CVE n'est plus présente
- Mettre à jour le statut de la CVE dans la plateforme (bouton **Résolu**)

### 6. Lessons Learned
- Documenter la CVE, les systèmes patchés et la date de remédiation
- Générer le rapport post-incident

## Références MITRE ATT&CK
- T1190 — Exploit Public-Facing Application
- T1203 — Exploitation for Client Execution
- T1068 — Exploitation for Privilege Escalation
