# Mini-SOC — Plateforme de détection et réponse aux incidents

Plateforme SOC (Security Operations Center) miniature combinant la stack ELK,
un moteur de détection par ensemble de modèles IA, et un module SOAR pour
l'automatisation de la réponse à incident.

## Architecture

3 machines virtuelles (KVM/libvirt) :
- **SOC** : Elasticsearch · Logstash · Kibana · Flask · moteurs IA
- **Victime** : Apache · DVWA · SSH · Filebeat · Suricata
- **Attaquant** : Hydra · Nmap · Nikto · SQLMap

Schémas d'architecture disponibles : [architecture_mini_soc.drawio](docs/architecture_mini_soc.drawio),
[incident_lifecycle.drawio](docs/incident_lifecycle.drawio), [workflow_analyste_soc.drawio](docs/workflow_analyste_soc.drawio)
(ouvrables avec [draw.io](https://app.diagrams.net/)).

Documentation technique complète (formules ML, RAG, RBAC/NIST, MITRE, déploiement) : [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md).

## Détection — Ensemble de 4 modèles

| Modèle | Type | Poids |
|---|---|---|
| Isolation Forest | Non supervisé | 0.30 |
| Random Forest / XGBoost | Supervisé | 0.35 |
| Autoencoder (Deep Learning) | Reconstruction error | 0.20 |
| Rate Detector | Volume/seuil | 0.15 |

Un incident n'est créé que si au moins 2 modèles sur 4 votent au-dessus de
leur seuil individuel — réduit les faux positifs par rapport à un détecteur
unique.

## Réponse — SOAR & RBAC

- **Auto-assignation** par sévérité : CRITICAL → L3, HIGH → L2, MEDIUM/LOW → L1
- **Notifications email** automatiques routées par niveau d'analyste
- **Blocage IP** automatique ou manuel (iptables) depuis l'interface
- **RBAC** à 3 niveaux (L1/L2/L3) + rôle Manager
- **Rapports PDF** et lessons-learned pour la phase Recover (NIST CSF)

## Stack technique

Python 3 / Flask · Elasticsearch 8.13 · Logstash · Kibana · Filebeat ·
scikit-learn · TensorFlow/Keras · Ollama (analyse LLM des incidents)

## Installation

```bash
cd mini-soc
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # renseigner ES_PASSWORD, FLASK_SECRET, etc.
./start_soc.sh
```

L'interface est servie sur `http://localhost:5000`.

### Comptes de démonstration

| Utilisateur | Niveau | Mot de passe |
|---|---|---|
| `admin` | L3 | `ChangeMe123!` |
| `analyst_l2` | L2 | `ChangeMe123!` |
| `analyst_l1` | L1 | `ChangeMe123!` |
| `manager` | Manager | `ChangeMe123!` |

À changer immédiatement après le premier déploiement (`mini-soc/users.json`).

## Scripts de démonstration

Le dossier [scripts/](scripts/) contient des scénarios d'attaque prêts à
l'emploi pour tester la détection de bout en bout :

1. `01_lancer_plateforme.sh` — démarrage de tous les services
2. `02_attaques_bruyantes.sh` — brute force SSH détecté par Kibana + IA
3. `03_attaques_stealth_ia_only.sh` — attaques lentes, détectées par l'IA uniquement
4. `04_killchain_postexploit.sh` — chaîne d'attaque complète avec post-exploitation
5. `05_test_email_critique.sh` — test du routage d'email par sévérité

## Couverture NIST Cybersecurity Framework

| Phase | Implémentation |
|---|---|
| Identify | Scan CVE, inventaire des mesures, threat hunting |
| Protect | RBAC, bcrypt, rate limiting, blocage IP préventif |
| Detect | 4 détecteurs IA en parallèle + vote d'ensemble |
| Respond | Auto-incident, email, SOAR block_ip, audit log |
| Recover | Rapport PDF, lessons learned, SLA tracking |

## Mapping MITRE ATT&CK

- `T1110` Brute Force / `T1110.001` Password Guessing / `T1110.004` Credential Stuffing
- `T1078` Valid Accounts

## Limites connues

Prototype académique validé en laboratoire (volume de logs limité, scénarios d'attaque
prédéfinis) — pas un remplaçant direct d'un SOC commercial en production. Détail complet
dans [docs/DOCUMENTATION.md § 22](docs/DOCUMENTATION.md#22-limites-connues--perspectives).

## Licence

MIT — voir [LICENSE](LICENSE). Projet académique (PFA) à but pédagogique, INPT 2025–2026.
