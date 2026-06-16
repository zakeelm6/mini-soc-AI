# Mini-SOC PFA — Améliorations & Corrections à Apporter

> **Priorité** : 🔴 Critique · 🟠 Important · 🟡 Moyen · 🟢 Bonus  
> **Date** : 2026-05-17

---

## 🔴 CRITIQUE — Sécurité & Stabilité

### 1. App Password Gmail exposé
**Problème** : L'App Password SMTP a été écrit dans le terminal/chat lors d'une session précédente.  
**Action** :  
1. Aller sur [myaccount.google.com](https://myaccount.google.com) → Sécurité → Mots de passe des applications
2. Révoquer l'App Password actuel
3. En générer un nouveau
4. Mettre à jour dans `config.py` ou `.env` (ne jamais écrire en clair dans le code)

### 2. Secret Key Flask en dur
**Problème** : `app.secret_key` est une valeur statique dans `app.py`.  
**Action** : Passer via variable d'environnement :
```python
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
```

### 3. Elasticsearch sans authentification
**Problème** : ES écoute sur `localhost:9200` sans user/password (mode développement).  
**Action** : Activer `xpack.security.enabled: true` dans `elasticsearch.yml` et créer des utilisateurs.

### 4. Flask en mode développement (debug=False mais dev server)
**Problème** : `app.run(threaded=True)` est le serveur de développement Werkzeug, pas production.  
**Action** : Remplacer par Gunicorn :
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 300 app:app
```

---

## 🟠 IMPORTANT — Fonctionnalités manquantes

### 5. NIST PR.MA — Maintenance à 60% (seule lacune restante)
**Problème** : Aucun CVE n'est marqué `status=resolved` → maintenance non prouvée.  
**Action** : Ajouter un bouton "Marquer CVE résolu" sur la page `/cve` qui met à jour `status=resolved` dans ES.

### 6. NIST RC.RP — Seulement 3 incidents clôturés
**Problème** : La plupart des incidents sont `in_progress` mais jamais `closed`.  
**Action** : Ajouter un workflow de clôture : bouton "Clôturer" sur la page incident → demande une résolution → status=closed.

### 7. soc-blocked-ips — 1 seule entrée
**Problème** : Le blocage iptables via le bouton "Mitigate" doit indexer dans `soc-blocked-ips`.  
**Vérifier** : `auto_mitigate()` dans `app.py` contient-il bien le code d'indexation ES ?  
**Action** : Ajouter aussi une liste des IPs bloquées sur la page `/postexploit` (section "IPs mitigées").

### 8. Bot Ollama — temps de réponse très long (CPU-only)
**Problème** : llama3 8B sur CPU prend 2-5 minutes pour la première réponse.  
**Actions possibles** :
- Utiliser `llama3:8b-instruct-q2_K` (modèle plus léger)
- Passer sur `phi3:mini` ou `gemma2:2b` pour des réponses rapides
- Ajouter un GPU si disponible
- Afficher un message clair "Analyse en cours... (~2min sur CPU)" pendant le streaming

### 9. Polling bot `/api/postexploit/latest` — sessions non authentifiées
**Problème** : Le polling toutes les 30s retourne 302 si la session expire.  
**Action** : Dans `base.html`, si le poll retourne 302/401, arrêter le polling et afficher un message "Session expirée".

### 10. postexploit_detector.py — redémarrage manuel requis
**Problème** : Si le processus crashe, personne ne sait et la détection s'arrête.  
**Action** : Créer un service systemd :
```ini
[Unit]
Description=Mini-SOC Post-Exploit Detector

[Service]
WorkingDirectory=/home/arthur-leywin/mini-soc
ExecStart=/home/arthur-leywin/mini-soc/venv/bin/python postexploit_detector.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## 🟡 MOYEN — UX & Qualité

### 11. Incidents — bulk triage manquant
**Problème** : On ne peut trier qu'un incident à la fois.  
**Action** : Ajouter une case à cocher sur chaque ligne + bouton "Fermer sélectionnés" / "Assigner à..." en masse.

### 12. Page `/postexploit` — NIST ne se rafraîchit pas automatiquement
**Problème** : Les scores NIST sont chargés une seule fois au chargement de la page.  
**Action** : Ajouter un bouton "Rafraîchir" ou un auto-refresh toutes les 60s avec animation.

### 13. Logs SSH — pas de filtre par source IP dans l'UI
**Problème** : La page `/logs` montre tous les logs sans filtre rapide par IP.  
**Action** : Ajouter des filtres rapides : IP, hostname, type de log, période.

### 14. CVE — pas de lien vers NVD/Mitre
**Problème** : Les CVE affichés n'ont pas de lien direct vers la base officielle.  
**Action** : Ajouter `<a href="https://nvd.nist.gov/vuln/detail/{cve_id}">` sur chaque CVE.

### 15. Email post-exploit — pas d'accusé de réception dans ES
**Problème** : Les emails envoyés par `send_postexploit_alert()` ne sont pas indexés dans `soc-notifications`.  
**Action** : Ajouter dans `notifier.py` après chaque envoi :
```python
es.index(index="soc-notifications", document={
    "@timestamp": now, "type": "postexploit_alert",
    "recipient": email, "ip": ip, "technique": technique
})
```

### 16. Audit log — actions insuffisantes tracées
**Problème** : Seules les connexions sont dans `soc-audit-log`. Les actions (triage, blocage, etc.) ne sont pas toutes tracées.  
**Action** : Tracer systématiquement : changement de statut d'incident, blocage IP, reset password, création/suppression user.

### 17. Page incidents — pas de pagination côté serveur
**Problème** : La page `/incidents` charge tous les incidents en mémoire.  
**Action** : Implémenter une pagination ES avec `search_after` ou `from/size` + boutons "Page suivante".

### 18. Rapport post-incident — format PDF
**Problème** : Les rapports sont du texte brut dans ES, pas exportables.  
**Action** : Utiliser `weasyprint` ou `reportlab` pour générer un PDF téléchargeable via le bouton "Rapport".

---

## 🟢 BONUS — Améliorations avancées

### 19. Multi-tenant / équipes
**Idée** : Ajouter un concept d'"équipe" ou de "shift" SOC avec rotation des analystes et historique par shift.

### 20. Threat Hunting manuel
**Idée** : Ajouter une page `/hunting` avec un éditeur de requêtes Elasticsearch pour que les L2/L3 puissent faire du threat hunting libre.

### 21. Timeline interactive
**Idée** : Sur la page incident, ajouter une timeline verticale montrant l'évolution des événements liés à cette IP (logs → anomalie → PE → blocage).

### 22. Dashboard Kibana intégré
**Problème** : La page `/kibana` est juste un iframe basique.  
**Action** : Créer des dashboards Kibana dédiés (auth.log, anomalies, kill chain) et les intégrer avec l'authentification SSO.

### 23. Alertes Slack/Discord
**Action** : Le notifier.py a déjà un placeholder webhook. Compléter avec :
```python
requests.post(webhook_url, json={"text": f"🚨 Post-exploit: {ip} — {technique}"})
```

### 24. Score de risque dynamique par IP
**Idée** : Calculer un "risk score" par IP basé sur : nombre d'anomalies + PE events + CVE liés + dernière connexion. Afficher sur la page `/postexploit`.

### 25. Auto-réponse complète (SOAR basique)
**Idée** : Quand un PE critique est détecté, déclencher automatiquement :
1. Blocage IP (iptables)
2. Envoi email
3. Création incident
4. Analyse Ollama
5. Notification bot

Actuellement seuls 1, 2, 3 sont automatiques. Ajouter 4 et 5.

### 26. Filebeat health check
**Idée** : Ajouter une route `/api/health/filebeat` qui vérifie si des logs ont été reçus dans les 5 dernières minutes. Afficher un indicateur rouge sur le dashboard si Filebeat est down.

### 27. Chiffrement des données sensibles
**Action** : Chiffrer les champs email dans `users.json` et les informations sensibles dans les incidents (IPs, patterns) via `cryptography.fernet`.

---

## Récapitulatif des priorités

| # | Priorité | Action | Effort |
|---|---|---|---|
| 1 | 🔴 | Révoquer et renouveler l'App Password Gmail | 5min |
| 2 | 🔴 | Secret key Flask en variable d'environnement | 10min |
| 5 | 🟠 | Bouton "Marquer CVE résolu" → NIST PR.MA 100% | 1h |
| 6 | 🟠 | Workflow clôture incidents → NIST RC.RP 100% | 2h |
| 8 | 🟠 | Modèle Ollama plus léger (gemma2:2b ou phi3:mini) | 30min |
| 10 | 🟠 | Service systemd pour postexploit_detector | 20min |
| 15 | 🟡 | Indexer emails PE dans soc-notifications | 30min |
| 18 | 🟡 | Export PDF des rapports post-incident | 3h |
| 25 | 🟢 | SOAR basique complet (auto-réponse) | 4h |
| 21 | 🟢 | Timeline interactive par incident/IP | 4h |

---

*Généré le 2026-05-17 — Mini-SOC PFA*
