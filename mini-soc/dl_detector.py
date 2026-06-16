"""
dl_detector.py — Détecteur Autoencoder Dense (Deep Learning)

Architecture : MLPRegressor entraîné à reconstruire ses propres entrées.
  Encoder : n_features → 16 → 8
  Decoder : 8 → 16 → n_features
  Loss     : MSE de reconstruction (erreur élevée = anomalie)

Entraînement : baseline now-25h → now-1h  (trafic supposé normal)
Détection    : fenêtre now-10m → now
Seuil        : mean_train_loss + 2 * std_train_loss

Les anomalies sont indexées dans soc-dl-anomalies et transmises à Flask.
"""
import os
import time
import json
import logging
import joblib
import requests
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, exceptions
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from config import ES_HOST, ES_USER, ES_PASSWORD, FLASK_URL

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s dl_detector — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("dl_detector")

MODEL_PATH     = os.path.join(os.path.dirname(__file__), "autoencoder.pkl")
THRESHOLD_PATH = os.path.join(os.path.dirname(__file__), "autoencoder_threshold.json")

RETRAIN_INTERVAL = 6 * 3600
DETECT_INTERVAL  = 60
MIN_TRAIN_LOGS   = 50
MIN_DETECT_LOGS  = 5
THRESHOLD_STD_K  = 2.0   # seuil = mean + K * std des pertes sur baseline
THRESHOLD_MIN    = 0.05  # floor pour éviter seuil~0 quand le modèle overfite la baseline

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))

_last_train_time = 0
_incident_seen   = {}


# ─── FEATURES (identiques à ia_detector pour comparaison équitable) ───────────

def extract_features(logs):
    if not logs:
        return pd.DataFrame()

    df = pd.DataFrame(logs)
    ft = pd.DataFrame(index=df.index)
    n = max(len(df), 1)

    # req_fraction : fraction des événements du batch provenant de cette IP (0-1)
    if "src_ip" in df.columns:
        counts = df["src_ip"].fillna("").value_counts()
        ft["req_fraction"] = df["src_ip"].fillna("").map(counts).fillna(1) / n
    else:
        ft["req_fraction"] = 1.0 / n

    # http_fraction : fraction des requêtes HTTP par clientip
    if "clientip" in df.columns:
        n_http = max((df["clientip"].notna() & (df["clientip"].ne(""))).sum(), 1)
        counts = df["clientip"].fillna("").value_counts()
        ft["http_fraction"] = df["clientip"].fillna("").map(counts).fillna(0) / n_http
    else:
        ft["http_fraction"] = 0.0

    # error_rate : taux de réponses 4xx/5xx par IP
    if "response" in df.columns and "clientip" in df.columns:
        codes = pd.to_numeric(df["response"], errors="coerce").fillna(0)
        df["_is_error"] = ((codes >= 400) & (codes < 600)).astype(int)
        df["_cip"] = df["clientip"].fillna("")
        err_rate = df.groupby("_cip")["_is_error"].mean()
        ft["error_rate"] = df["_cip"].map(err_rate).fillna(0)
    else:
        ft["error_rate"] = 0.0

    # bytes_total : volume de données (log-normalisé)
    if "bytes" in df.columns:
        ft["bytes_total"] = np.log1p(pd.to_numeric(df["bytes"], errors="coerce").fillna(0))
    else:
        ft["bytes_total"] = 0.0

    # auth_fraction : fraction des events auth provenant de cette IP
    if "log_type" in df.columns and "src_ip" in df.columns:
        auth_mask = df["log_type"].fillna("") == "auth"
        n_auth = max(auth_mask.sum(), 1)
        auth_counts = df.loc[auth_mask, "src_ip"].value_counts()
        ft["auth_fraction"] = df["src_ip"].fillna("").map(auth_counts).fillna(0) / n_auth
    else:
        ft["auth_fraction"] = 0.0

    return ft.fillna(0).astype(float)


# ─── FETCH ────────────────────────────────────────────────────────────────────

def fetch_logs(start, end, size=5000):
    try:
        r = es.search(
            index="soc-logs-*",
            size=size,
            query={"range": {"@timestamp": {"gte": start, "lte": end}}}
        )
        return [h["_source"] for h in r["hits"]["hits"]]
    except exceptions.NotFoundError:
        return []
    except Exception as e:
        log.error(f"fetch_logs: {e}")
        return []


# ─── ENTRAÎNEMENT ─────────────────────────────────────────────────────────────

def _fetch_llm_normal_logs(size=1000):
    """
    Récupère les logs des IPs confirmées FP par Ollama.
    Ces logs représentent du trafic que le LLM a jugé normal →
    les inclure dans la baseline améliore la définition du "normal" pour l'autoencoder.
    """
    try:
        r = es.search(
            index="soc-incidents",
            size=200,
            query={"bool": {"must": [
                {"exists": {"field": "src_ip"}},
            ], "should": [
                {"term": {"llm_verdict.keyword": "false_positive"}},
                {"term": {"ai_analysis.verdict.keyword": "false_positive"}},
            ], "minimum_should_match": 1}},
            _source=["src_ip", "llm_confidence", "ai_analysis"],
        )
        fp_ips = [
            h["_source"]["src_ip"]
            for h in r["hits"]["hits"]
            if float(h["_source"].get("llm_confidence") or
                     (h["_source"].get("ai_analysis") or {}).get("confidence") or 0) >= 0.75
            and h["_source"].get("src_ip")
        ]
        if not fp_ips:
            return []

        # Récupérer les vrais logs de ces IPs
        r2 = es.search(
            index="soc-logs-*",
            size=size,
            query={"bool": {"must": [
                {"terms": {"src_ip": list(set(fp_ips))}},
                {"range": {"@timestamp": {"gte": "now-48h"}}}
            ]}},
        )
        logs = [h["_source"] for h in r2["hits"]["hits"]]
        log.info(f"Logs FP LLM : {len(logs)} logs normaux validés par Ollama ({len(set(fp_ips))} IPs)")
        return logs
    except Exception as e:
        log.error(f"Erreur fetch logs FP LLM: {e}")
        return []


def _fetch_llm_attack_ips():
    """Retourne les IPs confirmées TP par Ollama — à exclure de la baseline normale."""
    try:
        r = es.search(
            index="soc-incidents",
            size=200,
            query={"bool": {"must": [
                {"exists": {"field": "src_ip"}},
            ], "should": [
                {"term": {"llm_verdict.keyword": "true_positive"}},
                {"term": {"ai_analysis.verdict.keyword": "true_positive"}},
            ], "minimum_should_match": 1}},
            _source=["src_ip"],
        )
        return set(h["_source"]["src_ip"] for h in r["hits"]["hits"] if h["_source"].get("src_ip"))
    except Exception:
        return set()


def train_autoencoder(logs, extra_normal_logs=None):
    """
    Entraîne un autoencoder dense sur les logs de baseline.
    extra_normal_logs : logs FP validés par Ollama, ajoutés à la baseline pour élargir
    la définition du "normal" et réduire les faux positifs DL.
    """
    # Fusionner baseline + logs normaux validés LLM
    if extra_normal_logs:
        combined = logs + extra_normal_logs
        log.info(f"Baseline enrichie: {len(logs)} baseline + {len(extra_normal_logs)} FP LLM = {len(combined)} total")
        logs = combined

    features = extract_features(logs)
    if features.empty or features.shape[0] < MIN_TRAIN_LOGS:
        log.warning(f"Données insuffisantes pour entraîner ({features.shape[0]} logs)")
        return None, None, None, []

    n_features = features.shape[1]
    scaler = StandardScaler()
    X = scaler.fit_transform(features.values)

    # Autoencoder: input → 16 → 8 → 16 → input
    autoencoder = MLPRegressor(
        hidden_layer_sizes=(16, 8, 16),
        activation="relu",
        solver="adam",
        max_iter=500,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.1,
        n_iter_no_change=20
    )
    autoencoder.fit(X, X)

    # Calcul du seuil sur la baseline
    X_reconstructed = autoencoder.predict(X)
    losses = np.mean((X - X_reconstructed) ** 2, axis=1)
    threshold = float(max(
        np.mean(losses) + THRESHOLD_STD_K * np.std(losses),
        np.percentile(losses, 99),
        THRESHOLD_MIN
    ))

    col_names = list(features.columns)
    data = {"autoencoder": autoencoder, "scaler": scaler, "feature_columns": col_names}
    joblib.dump(data, MODEL_PATH)
    with open(THRESHOLD_PATH, "w") as f:
        json.dump({"threshold": threshold, "train_mean": float(np.mean(losses)),
                   "train_std": float(np.std(losses))}, f, indent=2)

    log.info(f"Autoencoder entraîné sur {features.shape[0]} logs | seuil MSE={threshold:.6f}")
    return autoencoder, scaler, threshold, col_names


def load_or_train():
    if os.path.exists(MODEL_PATH) and os.path.exists(THRESHOLD_PATH):
        try:
            data = joblib.load(MODEL_PATH)
            with open(THRESHOLD_PATH) as f:
                tdata = json.load(f)
            log.info(f"Autoencoder chargé | seuil MSE={tdata['threshold']:.6f}")
            return data["autoencoder"], data["scaler"], tdata["threshold"], data["feature_columns"]
        except Exception as e:
            log.warning(f"Modèle corrompu ({e}) — réentraînement...")

    log.info("Entraînement initial sur baseline (now-25h → now-1h)...")
    logs = fetch_logs("now-25h", "now-1h", size=5000)

    # Exclure les logs des IPs confirmées attaquantes par Ollama de la baseline
    attack_ips = _fetch_llm_attack_ips()
    if attack_ips:
        before = len(logs)
        logs = [l for l in logs if l.get("src_ip", "") not in attack_ips]
        log.info(f"Exclusion IPs TP LLM : {before} → {len(logs)} logs baseline")

    # Enrichir la baseline avec les logs FP validés par Ollama
    extra_normal = _fetch_llm_normal_logs()

    if len(logs) < MIN_TRAIN_LOGS:
        log.warning(f"Baseline insuffisante ({len(logs)} logs) — retry dans 60s")
        return None, None, None, []
    return train_autoencoder(logs, extra_normal_logs=extra_normal)


# ─── DÉTECTION ────────────────────────────────────────────────────────────────

def run_detection(autoencoder, scaler, threshold, feature_columns):
    global _incident_seen

    logs = fetch_logs("now-10m", "now", size=1000)
    if len(logs) < MIN_DETECT_LOGS:
        log.info(f"Pas assez de logs récents ({len(logs)}) — skip")
        return

    features = extract_features(logs)
    if features.empty:
        return

    for col in feature_columns:
        if col not in features.columns:
            features[col] = 0.0
    features = features[feature_columns]

    X = scaler.transform(features.values)
    X_reconstructed = autoencoder.predict(X)
    losses = np.mean((X - X_reconstructed) ** 2, axis=1)

    # Normaliser le score: loss/threshold clippé à [0,1] puis [0-1]
    scores = np.clip(losses / (threshold + 1e-9), 0, 3.0) / 3.0

    # Calculer l'IP dominante du batch pour enrichir les logs sans IP
    ip_counts = {}
    for l in logs:
        ipl = l.get("src_ip", "")
        if ipl:
            ip_counts[ipl] = ip_counts.get(ipl, 0) + 1
    dominant_ip = None
    if ip_counts:
        top_ip     = max(ip_counts, key=lambda k: ip_counts[k])
        top_count  = ip_counts[top_ip]
        total_w_ip = sum(ip_counts.values())
        if total_w_ip > 0 and top_count / total_w_ip >= 0.5:
            dominant_ip = top_ip
            log.debug(f"IP dominante DL : {dominant_ip} ({top_count}/{total_w_ip})")

    anomaly_count = 0
    for i, (loss, score) in enumerate(zip(losses, scores)):
        if loss <= threshold:
            continue

        src_ip   = logs[i].get("src_ip", "") or (dominant_ip or "")
        log_type = logs[i].get("log_type", "unknown")
        ts       = logs[i].get("@timestamp", datetime.now(timezone.utc).isoformat())
        severity = "critical" if score >= 0.7 else "high" if score >= 0.4 else "medium"

        try:
            es.index(index="soc-dl-anomalies", document={
                "@timestamp":       ts,
                "anomaly_score":    round(float(score), 4),
                "reconstruction_loss": round(float(loss), 6),
                "threshold":        round(threshold, 6),
                "src_ip":           src_ip,
                "log_type":         log_type,
                "ssh_user":         logs[i].get("ssh_user", ""),
                "severity":         severity,
                "alert_type":       "autoencoder",
                "features":         {col: float(features.iloc[i][col]) for col in feature_columns}
            })
        except Exception as e:
            log.error(f"Indexation DL anomalie: {e}")

        # Dédup incident : 1 par IP par heure
        hour_key = f"dl_{src_ip}_{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H')}"
        if hour_key not in _incident_seen:
            _incident_seen[hour_key] = True
            if len(_incident_seen) > 500:
                _incident_seen.clear()
            try:
                resp = requests.post(f"{FLASK_URL}/api/auto_incident", json={
                    "anomaly_score": float(score),
                    "timestamp":     ts,
                    "src_ip":        src_ip,
                    "log_type":      log_type,
                    "ssh_user":      logs[i].get("ssh_user", ""),
                    "severity":      severity,
                    "source":        "autoencoder"
                }, timeout=2)
                log.info(f"Incident DL: {src_ip} loss={loss:.6f} score={score:.3f} → {resp.json()}")
            except Exception as e:
                log.warning(f"Flask incident error: {e}")

        anomaly_count += 1

    log.info(f"Détection DL: {anomaly_count} anomalies / {len(logs)} logs (seuil MSE={threshold:.6f})")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("Démarré — Autoencoder Dense (Deep Learning)")
    log.info(f"  Architecture : n_features → 16 → 8 → 16 → n_features")
    log.info(f"  Train  : now-25h → now-1h  (baseline 24h)")
    log.info(f"  Detect : now-10m → now")
    log.info(f"  Seuil  : mean_loss + {THRESHOLD_STD_K} * std_loss")

    autoencoder, scaler, threshold, feature_columns = load_or_train()
    _last_train_time = time.time()

    while True:
        try:
            if time.time() - _last_train_time >= RETRAIN_INTERVAL:
                log.info("Re-entraînement périodique avec labels Ollama...")
                logs = fetch_logs("now-25h", "now-1h", size=5000)
                # Exclure les IPs attaquantes validées par Ollama
                attack_ips = _fetch_llm_attack_ips()
                if attack_ips:
                    logs = [l for l in logs if l.get("src_ip", "") not in attack_ips]
                # Enrichir avec les FP validés par Ollama
                extra_normal = _fetch_llm_normal_logs()
                if len(logs) >= MIN_TRAIN_LOGS:
                    autoencoder, scaler, threshold, feature_columns = train_autoencoder(
                        logs, extra_normal_logs=extra_normal)
                    log.info("DL ré-entraîné avec labels Ollama")
                else:
                    log.warning(f"Re-entraînement ignoré ({len(logs)} logs)")
                _last_train_time = time.time()

            if autoencoder is not None and feature_columns:
                run_detection(autoencoder, scaler, threshold, feature_columns)
            else:
                log.info("Pas de modèle — tentative d'entraînement...")
                autoencoder, scaler, threshold, feature_columns = load_or_train()

        except Exception as e:
            log.error(f"Erreur inattendue: {e}")

        time.sleep(DETECT_INTERVAL)
