"""
auto_labeler.py — Étiquetage automatique TP/FP par IA

Interroge périodiquement soc-incidents pour les incidents qui ont reçu une
analyse Ollama (llama3, confiance ≥ CONF_THRESHOLD, verdict ≠ uncertain) mais
dont le champ `verdict` est encore "none".

Actions automatiques :
  true_positive  → verdict = "true_positive", status → "in_progress" (si awaiting_action)
  false_positive → verdict = "false_positive", status → "closed"

Après AUTO_RETRAIN_THRESHOLD nouveaux labels, déclenche le ré-entraînement RF
via subprocess.
"""
import os
import sys
import time
import json
import logging
import subprocess
import threading
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

from config import ES_HOST, ES_USER, ES_PASSWORD

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s auto_labeler — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("auto_labeler")

CONF_THRESHOLD        = 0.75   # confiance minimale pour auto-labeler
CHECK_INTERVAL        = 120    # secondes entre chaque vérification
AUTO_RETRAIN_THRESHOLD = 3     # nouveaux labels avant ré-entraînement RF

STATS_PATH = os.path.join(os.path.dirname(__file__), "auto_labeler_stats.json")

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))

_stats_lock = threading.Lock()


# ─── STATS ────────────────────────────────────────────────────────────────────

def _load_stats():
    try:
        with open(STATS_PATH) as f:
            return json.load(f)
    except Exception:
        return {
            "total_auto_labeled": 0,
            "true_positives":     0,
            "false_positives":    0,
            "retrains_triggered": 0,
            "last_run":           None,
            "history":            [],
        }


def _save_stats(stats):
    with open(STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)


def _record(verdict, incident_id, src_ip, confidence):
    with _stats_lock:
        s = _load_stats()
        s["total_auto_labeled"] += 1
        if verdict == "true_positive":
            s["true_positives"] += 1
        else:
            s["false_positives"] += 1
        s["last_run"] = datetime.now(timezone.utc).isoformat()
        s["history"].append({
            "ts":          datetime.now(timezone.utc).isoformat(),
            "incident_id": incident_id,
            "src_ip":      src_ip,
            "verdict":     verdict,
            "confidence":  confidence,
        })
        # keep last 200 history entries
        if len(s["history"]) > 200:
            s["history"] = s["history"][-200:]
        _save_stats(s)


def _record_retrain():
    with _stats_lock:
        s = _load_stats()
        s["retrains_triggered"] += 1
        _save_stats(s)


# ─── CORE LOGIC ───────────────────────────────────────────────────────────────

def _fetch_unlabeled_analyzed(size=200):
    """
    Retourne les incidents avec:
      - ai_analysis.verdict = true_positive | false_positive
      - ai_analysis.model ≠ fallback
      - ai_analysis.confidence ≥ CONF_THRESHOLD
      - verdict = "none"  (pas encore étiqueté manuellement ou automatiquement)
    """
    try:
        r = es.search(
            index="soc-incidents",
            size=size,
            query={"bool": {
                "must": [
                    {"terms": {"ai_analysis.verdict.keyword": ["true_positive", "false_positive"]}},
                    {"term":  {"verdict.keyword": "none"}},
                ],
                "must_not": [
                    {"term": {"ai_analysis.model.keyword": "fallback"}},
                ],
            }},
            _source=["incident_id", "src_ip", "status", "verdict",
                     "ai_analysis", "llm_verdict", "llm_confidence", "title"],
        )
        return r["hits"]["hits"]
    except Exception as e:
        log.error(f"Erreur fetch incidents non étiquetés: {e}")
        return []


def _apply_label(doc_id, incident_id, verdict, current_status):
    """
    Applique le verdict auto sur l'incident ES.
    TP → status reste (ou passe à in_progress si awaiting_action)
    FP → status = closed
    """
    new_status = current_status
    if verdict == "true_positive" and current_status == "awaiting_action":
        new_status = "in_progress"
    elif verdict == "false_positive":
        new_status = "closed"

    try:
        es.update(
            index="soc-incidents",
            id=doc_id,
            body={"doc": {
                "verdict":        verdict,
                "status":         new_status,
                "auto_labeled":   True,
                "auto_labeled_at": datetime.now(timezone.utc).isoformat(),
                "updated_at":     datetime.now(timezone.utc).isoformat(),
            }},
        )
        return True
    except Exception as e:
        log.error(f"Erreur mise à jour incident {incident_id}: {e}")
        return False


def _trigger_rf_retrain():
    """Lance le ré-entraînement RF en mode --train-only dans un sous-processus."""
    script = os.path.join(os.path.dirname(__file__), "rf_detector.py")
    if not os.path.exists(script):
        log.warning("rf_detector.py introuvable — ré-entraînement ignoré")
        return
    try:
        log.info("Lancement ré-entraînement RF (--train-only)…")
        proc = subprocess.Popen(
            [sys.executable, script, "--train-only"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(__file__),
        )
        out, _ = proc.communicate(timeout=120)
        if out:
            for line in out.decode(errors="replace").strip().splitlines():
                log.info(f"  RF: {line}")
        log.info(f"Ré-entraînement RF terminé (exit={proc.returncode})")
        _record_retrain()
    except subprocess.TimeoutExpired:
        proc.kill()
        log.warning("Ré-entraînement RF timeout (120s) — tué")
    except Exception as e:
        log.error(f"Erreur ré-entraînement RF: {e}")


# ─── MAIN LOOP ────────────────────────────────────────────────────────────────

def run_once():
    hits = _fetch_unlabeled_analyzed()
    if not hits:
        log.info("Aucun incident à étiqueter automatiquement")
        return 0

    log.info(f"{len(hits)} incident(s) éligibles pour auto-étiquetage")
    labeled = 0

    for h in hits:
        src     = h["_source"]
        doc_id  = h["_id"]
        ai      = src.get("ai_analysis") or {}
        verdict = ai.get("verdict") or src.get("llm_verdict", "")
        conf    = float(ai.get("confidence") or src.get("llm_confidence") or 0)
        iid     = src.get("incident_id", doc_id)
        ip      = src.get("src_ip", "")
        status  = src.get("status", "awaiting_action")

        if verdict not in ("true_positive", "false_positive"):
            continue
        if conf < CONF_THRESHOLD:
            log.debug(f"  {iid} — confiance trop faible ({conf:.2f}) — ignoré")
            continue

        ok = _apply_label(doc_id, iid, verdict, status)
        if ok:
            labeled += 1
            action = "fermé (FP)" if verdict == "false_positive" else "confirmé TP"
            log.info(f"  [{iid}] {ip} → {verdict} (conf={conf:.2f}) — {action}")
            _record(verdict, iid, ip, conf)

    return labeled


def main():
    log.info("Démarré — Auto-étiquetage TP/FP par IA")
    log.info(f"  Seuil confiance  : {CONF_THRESHOLD}")
    log.info(f"  Intervalle check : {CHECK_INTERVAL}s")
    log.info(f"  Retrain seuil    : {AUTO_RETRAIN_THRESHOLD} nouveaux labels")

    new_labels_since_retrain = 0

    while True:
        try:
            labeled = run_once()
            if labeled > 0:
                new_labels_since_retrain += labeled
                log.info(f"{labeled} incident(s) étiquetés | cumul depuis dernier retrain: {new_labels_since_retrain}")

            if new_labels_since_retrain >= AUTO_RETRAIN_THRESHOLD:
                log.info(f"Seuil atteint ({new_labels_since_retrain} labels) → RF retrain")
                _trigger_rf_retrain()
                new_labels_since_retrain = 0

        except Exception as e:
            log.error(f"Erreur inattendue: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    # Support mode one-shot pour tests
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        n = run_once()
        print(f"{n} incident(s) étiquetés")
    else:
        main()
