# Guide de démo — Scénario Live « Attaque → Détection »
> Durée : 6–8 minutes · Objectif : montrer le flux complet en temps réel

---

## AVANT LA DÉMO — Checklist T-30min

```
[ ] Démarrer les VMs (attaquant + victime)
[ ] bash 01_lancer_plateforme.sh    # démarrer ELK + Flask + IA
[ ] Ouvrir Firefox → http://localhost:5000  (login: admin / ChangeMe123!)
[ ] Ouvrir un 2ème onglet → http://localhost:5601 (Kibana)
[ ] Ouvrir un terminal → ssh victim@<IP_VICTIME> (pour montrer les logs)
[ ] Ouvrir un terminal → ssh <user>@<IP_ATTAQUANT>  (terminal attaquant)
[ ] Nettoyer les anciens incidents si besoin : bash 00_reset_demo.sh
[ ] Tester : curl -s http://<IP_VICTIME> → doit répondre
```

---

## CHECKLIST T-5min (juste avant la démo)

```
[ ] Flask UP    : curl -s http://localhost:5000 → HTTP 302
[ ] ES UP       : curl -s -u elastic:$ES_PASSWORD http://localhost:9200/_cluster/health | python3 -c "import sys,json;h=json.load(sys.stdin);print(h['status'])"
[ ] IA UP       : pgrep -a ia_detector → doit exister
[ ] Rate UP     : pgrep -a rate_detector → doit exister
[ ] Victime UP  : ping -c1 <IP_VICTIME> → 0% loss
[ ] Attaquant UP: ping -c1 <IP_ATTAQUANT> → 0% loss
```

---

## SCÉNARIO DE DÉMO — 3 actes

### ACTE 1 — Avant (1 min)
**Écran : plateforme SOC, dashboard principal**

> "Voici notre plateforme Mini-SOC. En ce moment, l'état est nominal —
> zéro incident actif, les 4 détecteurs IA tournent en arrière-plan
> toutes les 60 secondes. Je vais maintenant lancer une vraie attaque
> depuis la machine attaquante."

→ Montrer le dashboard, la file de priorité vide (ou peu d'incidents)
→ Montrer le terminal rate_detector en live : `tail -f /tmp/rate.log`

---

### ACTE 2 — L'attaque (2–3 min)
**Ouvrir le terminal sur la VM attaquante**

#### Étape 2a — SSH Brute Force MASSIF (détecté par IA + Kibana)
```bash
# Sur la VM attaquante :
hydra -l root -P /usr/share/wordlists/rockyou.txt \
      ssh://<IP_VICTIME> \
      -t 4 -w 2 -f \
      -o /tmp/hydra_result.txt
```
> "Hydra lance un brute force SSH massif — plus de 10 tentatives par minute.
> Le Rate Detector va lever une alerte volumétrique immédiatement."

**En parallèle — montrer sur le SOC :**
- Onglet `tail -f /tmp/rate.log` → ligne « ALERT brute_force »
- Retour sur `/incidents` → incident apparaît automatiquement

---

#### Étape 2b — Scan de ports (après 30 secondes)
```bash
# Sur la VM attaquante :
nmap -A -T4 --open <IP_VICTIME>
```
> "En parallèle, Nmap scanne agressivement la victime.
> L'Isolation Forest détecte le pattern de connexions multi-ports."

---

#### Étape 2c — BONUS : attaque stealth (si le temps le permet)
```bash
# Sur le host SOC (fallback simulation) :
python3 mini-soc/simulate_attack.py
```
> "Maintenant une attaque furtive — seulement 7 tentatives SSH en 5 minutes.
> Kibana ne voit rien. Mais regardez sur notre plateforme..."
> → Montrer /stealth_compare : colonne « IA seul »

---

### ACTE 3 — La détection et la réponse (3–4 min)
**Écran : plateforme SOC `/incidents`**

#### Étape 3a — Incident créé
> "L'incident vient d'être créé automatiquement par l'IA Ensemble.
> Regardez : score 8.7/10 → sévérité CRITICAL.
> Assigné automatiquement à l'analyste L2 — SLA 15 minutes."

→ Cliquer sur l'incident → ouvrir la fiche détail

#### Étape 3b — Détail de l'incident
> "Dans la fiche, on voit les scores des 4 modèles :
> Isolation Forest 0.87, Random Forest 0.92, DL 0.79, Rate Detector déclenché.
> Et la technique MITRE ATT&CK identifiée : T1110 — Brute Force."

→ Montrer les 4 scores, la timeline des logs, l'IP attaquante

#### Étape 3c — Réponse SOAR (blocage IP)
> "Je valide ce True Positive et je bloque l'IP en un clic."

→ Cliquer "Valider TP" + bouton "Bloquer IP"
→ La règle iptables s'applique instantanément

#### Étape 3d — Générer le rapport PDF
> "À la clôture, le rapport PDF est généré automatiquement —
> sans aucune saisie manuelle. IP, score IA, technique MITRE, CVEs,
> actions effectuées, traçabilité complète. Prêt pour un audit."

→ Cliquer "Générer rapport" → ouvrir le PDF
→ Faire défiler les sections : résumé, scores, MITRE, logs bruts

---

### BONUS — SOC Bot (si question)
> "L'analyste peut interroger le SOC Bot en langage naturel."

```
Questions à taper en direct :
  "combien d'incidents critiques aujourd'hui ?"
  "explique l'incident le plus récent"
  "quelle est la technique MITRE associée au dernier incident ?"
  "recommande une action pour bloquer cette attaque"
```
→ Ouvrir /bot → taper la question → streaming de la réponse

---

## PLAN B — Si la VM attaquante ne répond pas

```bash
# Lancer la simulation depuis le host SOC :
cd mini-soc
python3 simulate_attack.py

# "Pour des raisons de contraintes réseau, je simule l'injection
#  de logs d'attaque directement — les 200 tentatives SSH brute force
#  arrivent maintenant dans Elasticsearch, exactement comme si Hydra
#  tournait sur la machine attaquante."
```

---

## PLAN B2 — Si Flask tombe pendant la démo

```bash
# Redémarrer Flask en 3 secondes :
pkill -f app.py; sleep 1
cd mini-soc
python3 app.py &
# Le watchdog redémarre aussi automatiquement
```

---

## Timing recommandé

| Temps | Action | Ce qu'on voit |
|-------|--------|---------------------|
| 0:00 | Dashboard propre | Système nominal |
| 0:30 | Lancer Hydra | Terminal attaquant |
| 1:00 | Incident apparaît | Notification + file priorité |
| 1:30 | Ouvrir fiche incident | Scores 4 modèles |
| 2:30 | Bloquer IP | SOAR en action |
| 3:00 | Générer PDF | Rapport complet |
| 4:00 | Stealth attack (optionnel) | /stealth_compare |
| 5:00 | SOC Bot démo | Réponse LLM en streaming |

---

## Phrase finale

> "En moins de 60 secondes, notre plateforme a détecté l'attaque, créé
> l'incident, notifié l'analyste, bloqué l'IP et généré le rapport —
> entièrement automatiquement, sans aucune intervention manuelle.
> C'est ça, l'objectif d'un SOC intelligent open source."
