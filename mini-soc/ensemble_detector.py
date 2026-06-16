"""
ensemble_detector.py — Détecteur d'ensemble (IF + RF + DL + Rate)

Combine quatre modèles toutes les 60s :
  IF   → soc-anomalies        (Isolation Forest, non-supervisé)
  RF   → soc-rf-anomalies     (Random Forest supervisé, F1=1.0)
  DL   → soc-dl-anomalies     (Autoencoder, features numériques)
  Rate → soc-logs auth count  (volume brut SSH/5min)

Règle de vote :
  - score_ensemble = 0.30×IF + 0.35×RF + 0.20×DL + 0.15×rate_norm
  - Alerte seulement si au moins 2 modèles sur 4 dépassent leur seuil individuel
  → RF est le modèle le plus fiable (supervisé, F1=1.0)

Index de sortie : soc-ensemble-anomalies
"""
import os
import time
import logging
import requests
import numpy as np
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, exceptions

from config import ES_HOST, ES_USER, ES_PASSWORD, FLASK_URL
import meta_learner

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s ensemble — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("ensemble")

DETECT_INTERVAL = 60
WINDOW          = "10m"
RATE_WINDOW     = "5m"

# Seuils individuels pour compter un vote
IF_THRESHOLD   = 0.25   # IF score >= 0.25 → vote IF
RF_THRESHOLD   = 0.55   # RF proba >= 0.55 → vote RF
DL_THRESHOLD   = 0.30   # DL score >= 0.30 → vote DL
RATE_THRESHOLD = 10     # >= 10 auth logs/5min → vote Rate

# Seuil sur score final pour créer un incident
ENSEMBLE_THRESHOLD = 0.28
MIN_VOTES          = 2    # minimum de modèles sur 4 qui doivent voter

# Poids de chaque modèle (RF prioritaire car supervisé)
W_IF   = 0.30
W_RF   = 0.35
W_DL   = 0.20
W_RATE = 0.15

# Rate normalization: 50 auth/5min → score 1.0
RATE_NORM = 50.0

es          = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))
_seen       = {}   # dédup incidents


def _dedup(ip):
    key = f"{ip}_{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H')}"
    if key in _seen:
        return True
    _seen[key] = True
    if len(_seen) > 500:
        _seen.clear()
    return False


def _get_if_scores():
    """Score IF max par IP dans la fenêtre."""
    try:
        r = es.search(index="soc-anomalies", size=0,
            query={"range": {"@timestamp": {"gte": f"now-{WINDOW}"}}},
            aggs={"by_ip": {"terms": {"field": "src_ip.keyword", "size": 50},
                            "aggs": {"max_score": {"max": {"field": "anomaly_score"}}}}}
        )
        return {
            b["key"]: b["max_score"]["value"]
            for b in r["aggregations"]["by_ip"]["buckets"]
            if b["key"] and b["max_score"]["value"] is not None
        }
    except Exception as e:
        log.error(f"IF scores error: {e}")
        return {}


def _get_rf_scores():
    """Score RF max par IP dans la fenêtre."""
    try:
        r = es.search(index="soc-rf-anomalies", size=0,
            query={"range": {"@timestamp": {"gte": f"now-{WINDOW}"}}},
            aggs={"by_ip": {"terms": {"field": "src_ip.keyword", "size": 50},
                            "aggs": {"max_score": {"max": {"field": "anomaly_score"}}}}}
        )
        return {
            b["key"]: b["max_score"]["value"]
            for b in r["aggregations"]["by_ip"]["buckets"]
            if b["key"] and b["max_score"]["value"] is not None
        }
    except Exception as e:
        log.error(f"RF scores error: {e}")
        return {}


def _get_dl_scores():
    """Score DL max par IP dans la fenêtre."""
    try:
        r = es.search(index="soc-dl-anomalies", size=0,
            query={"range": {"@timestamp": {"gte": f"now-{WINDOW}"}}},
            aggs={"by_ip": {"terms": {"field": "src_ip.keyword", "size": 50},
                            "aggs": {"max_score": {"max": {"field": "anomaly_score"}}}}}
        )
        return {
            b["key"]: b["max_score"]["value"]
            for b in r["aggregations"]["by_ip"]["buckets"]
            if b["key"] and b["max_score"]["value"] is not None
        }
    except Exception as e:
        log.error(f"DL scores error: {e}")
        return {}


def _get_rate_counts():
    """Nombre de logs auth par IP dans RATE_WINDOW + max par minute (pour seuil Kibana)."""
    try:
        r = es.search(index="soc-logs*", size=0,
            query={"bool": {"must": [
                {"range": {"@timestamp": {"gte": f"now-{RATE_WINDOW}"}}}
            ], "should": [
                {"term":  {"log_type": "auth"}},
                {"match_phrase": {"message": "Failed password"}},
                {"match_phrase": {"message": "Invalid user"}},
                {"match_phrase": {"message": "authentication failure"}},
            ], "minimum_should_match": 1}},
            aggs={"by_ip": {"terms": {"field": "src_ip.keyword", "size": 50},
                            "aggs": {"per_min": {
                                "date_histogram": {
                                    "field": "@timestamp",
                                    "fixed_interval": "1m",
                                    "min_doc_count": 1,
                                }
                            }}}}
        )
        result = {}
        for b in r["aggregations"]["by_ip"]["buckets"]:
            if not b["key"]:
                continue
            max_1m = max((m["doc_count"] for m in b["per_min"]["buckets"]), default=0)
            result[b["key"]] = {"total": b["doc_count"], "max_1m": max_1m}
        return result
    except Exception as e:
        log.error(f"Rate counts error: {e}")
        return {}


def _get_sample_log(ip):
    """Retourne un log représentatif de l'IP pour les métadonnées."""
    try:
        r = es.search(index="soc-logs*", size=1,
            query={"bool": {"must": [
                {"term":  {"src_ip": ip}},
                {"range": {"@timestamp": {"gte": f"now-{WINDOW}"}}}
            ]}},
            sort=[{"@timestamp": {"order": "desc"}}]
        )
        if r["hits"]["hits"]:
            return r["hits"]["hits"][0]["_source"]
    except Exception:
        pass
    return {}


def run_ensemble():
    if_scores   = _get_if_scores()
    rf_scores   = _get_rf_scores()
    dl_scores   = _get_dl_scores()
    rate_counts = _get_rate_counts()

    # Union de toutes les IPs vues
    all_ips = set(if_scores) | set(rf_scores) | set(dl_scores) | set(rate_counts)
    if not all_ips:
        log.info("Aucune IP dans les fenêtres — skip")
        return

    anomaly_count = 0
    for ip in all_ips:
        if_s       = float(if_scores.get(ip, 0.0))
        rf_s       = float(rf_scores.get(ip, 0.0))
        dl_s       = float(dl_scores.get(ip, 0.0))
        rate_info  = rate_counts.get(ip, {"total": 0, "max_1m": 0})
        if isinstance(rate_info, dict):
            rate   = int(rate_info.get("total", 0))
            max_1m = int(rate_info.get("max_1m", 0))
        else:
            rate   = int(rate_info)
            max_1m = 0
        rate_s = min(1.0, rate / RATE_NORM)

        # Votes individuels
        vote_if   = 1 if if_s  >= IF_THRESHOLD   else 0
        vote_rf   = 1 if rf_s  >= RF_THRESHOLD   else 0
        vote_dl   = 1 if dl_s  >= DL_THRESHOLD   else 0
        vote_rate = 1 if rate  >= RATE_THRESHOLD  else 0
        votes     = vote_if + vote_rf + vote_dl + vote_rate

        # Si le rate est élevé (≥ 2× seuil = 20 auth/5min), il compte comme 2 votes :
        # brute force évident même sans confirmation des modèles IA
        if rate >= RATE_THRESHOLD * 2:
            votes = max(votes, 2)

        if votes < MIN_VOTES:
            continue

        # Détection rate-seul : bypass meta-learner (entraîné avec votes=2→FP)
        if vote_if == 0 and vote_rf == 0 and vote_dl == 0:
            ensemble_score = round(float(min(0.85, 0.30 + rate_s * 0.60)), 4)
        else:
            # Meta-learner remplace les poids fixes si disponible
            ensemble_score, score_source = meta_learner.predict(if_s, rf_s, dl_s, rate, votes)
            if score_source == "fallback":
                ensemble_score = W_IF * if_s + W_RF * rf_s + W_DL * dl_s + W_RATE * rate_s
                ensemble_score = round(float(min(1.0, ensemble_score)), 4)

        if ensemble_score < ENSEMBLE_THRESHOLD:
            continue

        severity = "critical" if ensemble_score >= 0.7 else "high" if ensemble_score >= 0.4 else "medium"
        sample   = _get_sample_log(ip)
        ts       = sample.get("@timestamp", datetime.now(timezone.utc).isoformat())
        log_type = sample.get("log_type", "auth")

        log.info(
            f"ENSEMBLE [{severity.upper()}]: {ip} | score={ensemble_score:.4f} "
            f"| IF={if_s:.3f}({vote_if}) RF={rf_s:.3f}({vote_rf}) "
            f"DL={dl_s:.3f}({vote_dl}) Rate={rate}({vote_rate}) | votes={votes}/4"
        )

        # Indexer dans soc-ensemble-anomalies
        try:
            es.index(index="soc-ensemble-anomalies", document={
                "@timestamp":     ts,
                "src_ip":         ip,
                "log_type":       log_type,
                "severity":       severity,
                "alert_type":     "ensemble",
                "ensemble_score": ensemble_score,
                "if_score":       if_s,
                "rf_score":       rf_s,
                "dl_score":       dl_s,
                "rate_count":     rate,
                "max_rate_1m":    max_1m,
                "rate_score":     rate_s,
                "votes":          votes,
                "vote_if":        vote_if,
                "vote_rf":        vote_rf,
                "vote_dl":        vote_dl,
                "vote_rate":      vote_rate,
            })
        except Exception as e:
            log.error(f"Index error: {e}")

        # Créer un incident (dédup par IP/heure)
        if not _dedup(ip):
            try:
                resp = requests.post(f"{FLASK_URL}/api/auto_incident_ensemble", json={
                    "anomaly_score": ensemble_score,
                    "timestamp":     ts,
                    "src_ip":        ip,
                    "log_type":      log_type,
                    "ssh_user":      sample.get("ssh_user", ""),
                    "severity":      severity,
                    "votes":         votes,
                    "if_score":      if_s,
                    "rf_score":      rf_s,
                    "dl_score":      dl_s,
                    "rate_count":    rate,
                }, timeout=3)
                log.info(f"Incident: {ip} → {resp.json()}")
            except Exception as e:
                log.warning(f"Flask error: {e}")

        anomaly_count += 1

    log.info(
        f"Ensemble: {anomaly_count} IPs anomales | "
        f"IF:{len(if_scores)} RF:{len(rf_scores)} DL:{len(dl_scores)} Rate:{len(rate_counts)} IPs vues"
    )


if __name__ == "__main__":
    log.info("Démarré — Ensemble (IF×0.30 + RF×0.35 + DL×0.20 + Rate×0.15)")
    log.info(f"  Seuils votes : IF≥{IF_THRESHOLD} | RF≥{RF_THRESHOLD} | DL≥{DL_THRESHOLD} | Rate≥{RATE_THRESHOLD}")
    log.info(f"  Condition    : ≥{MIN_VOTES}/4 modèles doivent voter")
    log.info(f"  Seuil final  : score≥{ENSEMBLE_THRESHOLD}")

    while True:
        try:
            run_ensemble()
        except Exception as e:
            log.error(f"Erreur: {e}")
        time.sleep(DETECT_INTERVAL)
