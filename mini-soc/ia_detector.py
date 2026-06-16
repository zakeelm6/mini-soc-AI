"""
ia_detector.py — Isolation Forest (features contenu + taux + ensemble)

Entraînement : now-25h → now-1h  (baseline pré-attaque — logs auth locaux)
Détection    : now-10m → now

Features extraites (contenu + volume par IP) :
  is_failed      — "failed" ou "failure" dans le message
  is_invalid_usr — "invalid user" dans le message
  is_sshd_auth   — "sshd" + auth context dans le message
  has_src_ip     — src_ip est non-vide (connexion distante)
  is_session_ok  — "session opened" dans le message (connexion normale)
  fail_rate_5m   — nombre de Failed password depuis cette IP sur 5 min (normalisé /50)
  ip_diversity   — fraction de users différents tentés par l'IP (diversité = scan user)
"""
import os
import time
import logging
import joblib
import requests
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, exceptions
from sklearn.ensemble import IsolationForest

from config import ES_HOST, ES_USER, ES_PASSWORD, FLASK_URL

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s ia_detector — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("ia_detector")

MODEL_PATH       = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")
RETRAIN_INTERVAL = 6 * 3600
DETECT_INTERVAL  = 60
MIN_TRAIN_LOGS   = 20
MIN_DETECT_LOGS  = 5
SCORE_THRESHOLD  = 0.25

FEATURE_COLS = ["is_failed", "is_invalid_usr", "is_sshd_auth", "has_src_ip", "is_session_ok"]

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))

_last_train_time = 0
_incident_seen   = {}


# ─── FETCH ────────────────────────────────────────────────────────────────────

def fetch_logs(start, end, size=5000):
    try:
        r = es.search(
            index="soc-logs,soc-logs-*",
            size=size,
            query={"range": {"@timestamp": {"gte": start, "lte": end}}}
        )
        return [h["_source"] for h in r["hits"]["hits"]]
    except exceptions.NotFoundError:
        return []
    except Exception as e:
        log.error(f"fetch_logs({start},{end}): {e}")
        return []


# ─── FEATURES ─────────────────────────────────────────────────────────────────

def _log_features(l):
    """Extrait le vecteur feature d'un seul log."""
    msg = str(l.get("message", "")).lower()
    ip  = str(l.get("src_ip", ""))

    is_failed      = 1.0 if ("failed" in msg or "failure" in msg or "error" in msg) else 0.0
    is_invalid_usr = 1.0 if "invalid user" in msg else 0.0
    is_sshd_auth   = 1.0 if ("sshd" in msg and ("auth" in msg or "password" in msg)) else 0.0
    has_src_ip     = 1.0 if ip else 0.0
    is_session_ok  = 1.0 if "session opened" in msg else 0.0

    return [is_failed, is_invalid_usr, is_sshd_auth, has_src_ip, is_session_ok]


def extract_features(logs):
    """1 ligne par log auth. Retourne (DataFrame, liste des logs auth sources)."""
    if not logs:
        return pd.DataFrame(), []

    auth_logs = [l for l in logs if l.get("log_type", "") == "auth"]
    if not auth_logs:
        return pd.DataFrame(), []

    rows = [_log_features(l) for l in auth_logs]
    ft   = pd.DataFrame(rows, columns=FEATURE_COLS).astype(float)
    return ft, auth_logs


# ─── ENTRAÎNEMENT ─────────────────────────────────────────────────────────────

def train_model(logs):
    features, auth_logs = extract_features(logs)
    if features.empty or len(auth_logs) < MIN_TRAIN_LOGS:
        log.warning(f"Données insuffisantes ({len(auth_logs)} auth logs) — entraînement ignoré")
        return None, []

    log.info(f"Baseline auth logs: {len(auth_logs)}")
    log.info(f"Moyennes features:\n{features.mean().to_string()}")
    log.info(f"Std features:\n{features.std().to_string()}")

    # Vérifier la variance
    if features.std().sum() < 0.01:
        log.warning("ATTENTION: features sans variance — modèle sera dégénéré!")

    model = IsolationForest(
        n_estimators=200,
        contamination=0.10,
        max_samples="auto",
        random_state=42
    )
    model.fit(features.values)

    # Sanity check (5 features: is_failed, is_invalid_usr, is_sshd_auth, has_src_ip, is_session_ok)
    normal = np.array([[0.05, 0.0, 0.0, 0.0, 0.4]])   # log local, session ouverte
    attack = np.array([[1.0,  1.0, 1.0, 1.0, 0.0]])   # SSH bruteforce depuis IP distante
    s_n = model.score_samples(normal)[0]
    s_a = model.score_samples(attack)[0]
    log.info(f"Sanity check: normal={s_n:.4f}, attaque={s_a:.4f}")
    if s_n <= s_a:
        log.warning("Modèle dégénéré: normal ≤ attaque en score! Vérifier les données d'entraînement.")

    data = {"model": model, "feature_columns": FEATURE_COLS}
    joblib.dump(data, MODEL_PATH)
    log.info(f"Modèle sauvegardé | features: {FEATURE_COLS}")
    return model, FEATURE_COLS


def load_or_train():
    if os.path.exists(MODEL_PATH):
        try:
            data = joblib.load(MODEL_PATH)
            m = data["model"]
            if hasattr(m, "estimators_") and data.get("feature_columns") == FEATURE_COLS:
                attack = np.array([[1.0, 1.0, 1.0, 1.0, 0.0]])
                normal = np.array([[0.05, 0.0, 0.0, 0.0, 0.4]])
                s_a = m.score_samples(attack)[0]
                s_n = m.score_samples(normal)[0]
                if abs(s_a + 0.5) < 1e-6 and abs(s_n + 0.5) < 1e-6:
                    log.warning("Modèle dégénéré détecté — réentraînement")
                else:
                    log.info(f"Modèle chargé | sanity: normal={s_n:.4f} attaque={s_a:.4f}")
                    return m, FEATURE_COLS
            else:
                log.warning("Format modèle incompatible — réentraînement")
        except Exception as e:
            log.warning(f"Erreur chargement ({e}) — réentraînement")

    log.info("Entraînement initial sur baseline (now-25h → now-1h)...")
    logs = fetch_logs("now-25h", "now-1h", size=5000)
    if len(logs) < MIN_TRAIN_LOGS:
        log.warning(f"Baseline insuffisante ({len(logs)} logs)")
        return None, []
    return train_model(logs)


# ─── DÉTECTION ────────────────────────────────────────────────────────────────

def run_detection(model, feature_columns):
    global _incident_seen

    logs = fetch_logs("now-10m", "now", size=2000)
    if len(logs) < MIN_DETECT_LOGS:
        log.info(f"Pas assez de logs ({len(logs)}) — skip")
        return

    features, auth_logs = extract_features(logs)
    if features.empty:
        log.info("Pas de logs auth dans la fenêtre — skip")
        return

    for col in feature_columns:
        if col not in features.columns:
            features[col] = 0.0
    features = features[feature_columns]

    raw_scores = model.decision_function(features.values)

    # Agréger par IP : score max parmi les logs de cette IP
    ip_best = {}  # ip → {score, raw, log, features}
    for i, l in enumerate(auth_logs):
        raw   = float(raw_scores[i])
        score = float(min(1.0, max(0.0, -raw / 0.5)))
        ip    = l.get("src_ip", "")

        if score < SCORE_THRESHOLD:
            continue

        if ip not in ip_best or ip_best[ip]["score"] < score:
            ip_best[ip] = {
                "score":    score,
                "raw":      raw,
                "log":      l,
                "features": features.iloc[i].to_dict(),
            }

    # Résoudre les anomalies sans IP — attribuer l'IP dominante du batch si elle couvre >50%
    if "" in ip_best:
        ip_counts = {}
        for l in auth_logs:
            ipl = l.get("src_ip", "")
            if ipl:
                ip_counts[ipl] = ip_counts.get(ipl, 0) + 1
        if ip_counts:
            dominant_ip    = max(ip_counts, key=lambda k: ip_counts[k])
            dominant_count = ip_counts[dominant_ip]
            total_with_ip  = sum(ip_counts.values())
            if total_with_ip > 0 and dominant_count / total_with_ip >= 0.5:
                log.info(f"IP dominante détectée : {dominant_ip} ({dominant_count}/{total_with_ip} logs) → attribuée aux anomalies sans IP")
                entry = ip_best.pop("")
                entry["log"]["src_ip"] = dominant_ip
                if dominant_ip not in ip_best or ip_best[dominant_ip]["score"] < entry["score"]:
                    ip_best[dominant_ip] = entry

    anomaly_count = 0
    for ip, info in ip_best.items():
        score    = info["score"]
        sample   = info["log"]
        ts       = sample.get("@timestamp", datetime.now(timezone.utc).isoformat())
        log_type = sample.get("log_type", "auth")
        severity = "critical" if score >= 0.7 else "high" if score >= 0.4 else "medium"
        feats    = info["features"]

        log.info(
            f"Anomalie: {ip!r} | score={score:.4f} [{severity}] | "
            f"failed={feats['is_failed']:.0f} invalid={feats['is_invalid_usr']:.0f} "
            f"remote={feats['has_src_ip']:.0f}"
        )

        try:
            es.index(index="soc-anomalies", document={
                "@timestamp":    ts,
                "anomaly_score": round(score, 4),
                "src_ip":        ip,
                "log_type":      log_type,
                "ssh_user":      sample.get("ssh_user", ""),
                "severity":      severity,
                "alert_type":    "isolation_forest",
                "features":      feats,
            })
        except Exception as e:
            log.error(f"Indexation: {e}")

        hour_key = f"{ip}_{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H')}"
        if hour_key not in _incident_seen:
            _incident_seen[hour_key] = True
            if len(_incident_seen) > 500:
                _incident_seen.clear()
            try:
                resp = requests.post(f"{FLASK_URL}/api/auto_incident", json={
                    "anomaly_score": score,
                    "timestamp":     ts,
                    "src_ip":        ip,
                    "log_type":      log_type,
                    "ssh_user":      sample.get("ssh_user", ""),
                    "severity":      severity,
                }, timeout=2)
                log.info(f"Incident créé: {ip} → {resp.json()}")
            except Exception as e:
                log.warning(f"Flask incident error: {e}")

        anomaly_count += 1

    log.info(f"Détection: {anomaly_count} IPs anomales / {len(auth_logs)} auth logs / {len(logs)} logs total")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Démarré — Isolation Forest (per-log content features)")
    log.info(f"  Seuil  : score >= {SCORE_THRESHOLD}")
    log.info(f"  Features: {FEATURE_COLS}")

    model, feature_columns = load_or_train()
    _last_train_time = time.time()

    while True:
        try:
            if time.time() - _last_train_time >= RETRAIN_INTERVAL:
                log.info("Re-entraînement périodique...")
                logs = fetch_logs("now-25h", "now-1h", size=5000)
                if len(logs) >= MIN_TRAIN_LOGS:
                    model, feature_columns = train_model(logs)
                _last_train_time = time.time()

            if model is not None and feature_columns:
                run_detection(model, feature_columns)
            else:
                log.info("Pas de modèle — tentative d'entraînement...")
                model, feature_columns = load_or_train()

        except Exception as e:
            log.error(f"Erreur inattendue: {e}")

        time.sleep(DETECT_INTERVAL)
