#!/bin/bash
# Backup quotidien Mini-SOC — modèles ML + index ES critiques
# Ajouter en crontab : 0 3 * * * /opt/mini-soc/backup_soc.sh >> /var/log/soc_backup.log 2>&1

set -euo pipefail

SOC_DIR="/opt/mini-soc"
BACKUP_BASE="$SOC_DIR/backups"
DATE=$(date +%Y%m%d_%H%M)
BACKUP_DIR="$BACKUP_BASE/$DATE"
KEEP_DAYS=7

ES_URL="http://localhost:9200"
ES_AUTH="elastic:changeme"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# ── Créer le répertoire de backup ───────────────────────────────────────────
mkdir -p "$BACKUP_DIR"
log "Backup démarré → $BACKUP_DIR"

# ── Modèles ML & fichiers critiques ─────────────────────────────────────────
for f in rf_model.pkl autoencoder.pkl llm_memory.json users.json incident_config.json vm_config.json; do
    src="$SOC_DIR/$f"
    if [ -f "$src" ]; then
        cp "$src" "$BACKUP_DIR/"
        log "  ✓ $f"
    else
        log "  ⚠ $f introuvable, ignoré"
    fi
done

# ── Backup index Elasticsearch (nécessite elasticdump) ──────────────────────
# npm install -g elasticdump  (si pas encore installé)
if command -v elasticdump &>/dev/null; then
    for index in soc-incidents soc-logs-labels soc-anomaly-labels soc-cve; do
        log "  ES dump : $index"
        elasticdump \
            --input="http://$ES_AUTH@localhost:9200/$index" \
            --output="$BACKUP_DIR/${index}.json" \
            --type=data \
            --limit=10000 2>>"$BACKUP_DIR/elasticdump.log" && log "    ✓ $index" || log "    ⚠ $index échoué"
    done
else
    log "  ⚠ elasticdump non installé — dump ES ignoré"
    log "    → installer : npm install -g elasticdump"
fi

# ── Snapshot ES natif (alternatif à elasticdump) ────────────────────────────
# Décommenter si les snapshots ES sont configurés :
# curl -s -X PUT "$ES_URL/_snapshot/soc_backup/snapshot_$DATE" \
#   -u "$ES_AUTH" -H 'Content-Type: application/json' \
#   -d '{"indices":"soc-incidents,soc-cve","ignore_unavailable":true}' | \
#   python3 -c "import sys,json; d=json.load(sys.stdin); print('ES snapshot:', d)" || true

# ── Compression du backup ────────────────────────────────────────────────────
tar -czf "$BACKUP_BASE/${DATE}.tar.gz" -C "$BACKUP_BASE" "$DATE"
rm -rf "$BACKUP_DIR"
log "Archive créée : ${DATE}.tar.gz ($(du -sh "$BACKUP_BASE/${DATE}.tar.gz" | cut -f1))"

# ── Nettoyage des anciens backups ────────────────────────────────────────────
find "$BACKUP_BASE" -name "*.tar.gz" -mtime +$KEEP_DAYS -delete
log "Nettoyage : archives > ${KEEP_DAYS} jours supprimées"

log "Backup terminé ✓"
