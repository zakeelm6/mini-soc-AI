# Mini-SOC — Déploiement Docker

## Prérequis

- Docker ≥ 24.0
- Docker Compose ≥ 2.20
- RAM : **minimum 8 GB** (ES 1 GB + Ollama 5 GB + Flask 500 MB)
- Stockage : **minimum 15 GB** (modèles Ollama ~7 GB + ES data)

---

## Démarrage rapide

```bash
# 1. Cloner / copier le projet
git clone <repo> mini-soc
cd mini-soc

# 2. Lancer tout
docker compose up -d

# 3. Suivre les logs (premier démarrage ~10 min pour télécharger les modèles)
docker compose logs -f
```

L'application sera disponible sur **http://localhost:5000**

---

## Ordre de démarrage automatique

```
elasticsearch  →  kibana
             ↘
              ollama  →  ollama-init (pull llama3 + gemma2 + nomic-embed-text)
                ↘
                 mini-soc  →  rag-init (construit l'index vectoriel)
```

> **Premier démarrage** : compter ~10–15 min pour le téléchargement des modèles Ollama.
> Les démarrages suivants sont instantanés (modèles en cache dans le volume `ollama_data`).

---

## Accès aux services

| Service | URL | Identifiants |
|---------|-----|-------------|
| Mini-SOC | http://localhost:5000 | voir `users.json` |
| Kibana | http://localhost:5601 | elastic / changeme |
| Elasticsearch | http://localhost:9200 | elastic / changeme |
| Ollama API | http://localhost:11434 | — |

---

## Commandes utiles

```bash
# Voir les logs d'un service
docker compose logs -f mini-soc
docker compose logs -f ollama-init

# Redémarrer un service
docker compose restart mini-soc

# Arrêter tout (données conservées dans les volumes)
docker compose down

# Arrêter et supprimer TOUT (volumes inclus — données perdues)
docker compose down -v

# Reconstruire l'image Flask après modification du code
docker compose build mini-soc
docker compose up -d mini-soc

# Accéder au shell de l'app
docker exec -it soc-app /bin/bash

# Reconstruire l'index RAG manuellement
docker exec -it soc-app /bin/sh -c "cd rag && python build_index.py"

# Tester Ollama
docker exec -it soc-ollama ollama list
```

---

## GPU Nvidia (optionnel — pour accélérer llama3)

Dans `docker-compose.yml`, décommenter la section `deploy` du service `ollama` :

```yaml
ollama:
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: 1
            capabilities: [gpu]
```

Installer le [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html) au préalable.

---

## Configuration

Modifier `.env` pour changer les credentials ou la clé Flask :

```env
ES_PASSWORD=mon-nouveau-mot-de-passe
FLASK_SECRET=une-cle-secrete-robuste
ABUSEIPDB_KEY=ma-cle-abuseipdb
```

---

## Structure des volumes

| Volume | Contenu |
|--------|---------|
| `es_data` | Données Elasticsearch (indices, logs) |
| `ollama_data` | Modèles Ollama (llama3, gemma2, nomic-embed) |
| `rag_vectors` | Base vectorielle ChromaDB (104 chunks SOC) |
| `soc_users` | Fichier users.json (comptes analystes) |
