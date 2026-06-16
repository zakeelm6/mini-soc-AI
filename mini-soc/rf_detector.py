"""
rf_detector.py — Random Forest supervisé pour détection d'attaques SSH/Web

Boucle d'apprentissage avec Ollama :
  - Les verdicts llama3 (true_positive / false_positive) sont lus depuis soc-incidents
  - Les IPs confirmées TP par Ollama sont ajoutées aux IPs attaquantes pour l'entraînement
  - Les IPs confirmées FP par Ollama sont explicitement exclues des labels attaque
  - Ré-entraînement automatique toutes les 6h si de nouveaux labels LLM sont disponibles
  → RF s'améliore au fil du temps même sur de nouvelles IPs jamais vues

Features :
  is_failed, is_invalid_usr, is_sshd_auth, has_src_ip,
  is_session_ok, hour_of_day, is_night, is_web_attack
"""
import os
import time
import pickle
import logging
import numpy as np
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, classification_report

from config import ES_HOST, ES_USER, ES_PASSWORD, FLASK_URL
import requests

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s rf — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("rf")

DETECT_INTERVAL = 60
WINDOW          = "10m"
MODEL_PATH      = os.path.join(os.path.dirname(__file__), "rf_model.pkl")
THRESHOLD       = 0.55   # probabilité minimum pour alerter
MIN_ATTACK_LOGS = 3      # au moins N logs suspects par IP avant alerte

ATTACK_IPS    = ["192.168.122.231", "192.168.122.1"]   # IPs attaquantes connues a priori
RETRAIN_INTERVAL = 6 * 3600   # ré-entraînement auto toutes les 6h si nouveaux labels LLM
_last_train_time = 0
_last_llm_count  = 0   # nb de labels LLM connus au dernier entraînement

FEATURE_COLS = [
    "is_failed", "is_invalid_usr", "is_sshd_auth",
    "has_src_ip", "is_session_ok", "hour_of_day", "is_night", "is_web_attack"
]

es      = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))
_seen   = {}


def _log_features(l):
    msg = str(l.get("message", "")).lower()
    ip  = str(l.get("src_ip", ""))
    ts  = str(l.get("@timestamp", ""))
    try:
        hour = int(ts[11:13])
    except Exception:
        hour = 12

    is_failed      = 1.0 if ("failed" in msg or "failure" in msg or "invalid" in msg) else 0.0
    is_invalid_usr = 1.0 if "invalid user" in msg else 0.0
    is_sshd_auth   = 1.0 if ("sshd" in msg and ("auth" in msg or "password" in msg)) else 0.0
    has_src_ip     = 1.0 if ip and ip != "None" else 0.0
    is_session_ok  = 1.0 if "session opened" in msg else 0.0
    hour_of_day    = float(hour) / 23.0
    is_night       = 1.0 if hour < 6 or hour >= 22 else 0.0
    is_web_attack  = 1.0 if any(x in msg for x in ["union select", "etc/passwd", ".php", "nikto", "sqlmap", "dirbuster"]) else 0.0

    return [is_failed, is_invalid_usr, is_sshd_auth, has_src_ip,
            is_session_ok, hour_of_day, is_night, is_web_attack]


def _get_llm_labeled_ips():
    """
    Lit les verdicts Ollama depuis soc-incidents pour enrichir les labels.
    Retourne (attack_ips, normal_ips) — deux sets d'IPs validés par le LLM.
    """
    attack_ips, normal_ips = set(), set()
    try:
        r = es.search(
            index="soc-incidents",
            size=500,
            query={"bool": {"must": [
                {"exists": {"field": "src_ip"}},
            ], "should": [
                {"terms": {"llm_verdict.keyword": ["true_positive", "false_positive"]}},
                {"terms": {"ai_analysis.verdict.keyword": ["true_positive", "false_positive"]}},
            ], "minimum_should_match": 1}},
            _source=["src_ip", "llm_verdict", "llm_confidence", "ai_analysis"],
        )
        for h in r["hits"]["hits"]:
            s    = h["_source"]
            ip   = s.get("src_ip", "").strip()
            ai   = s.get("ai_analysis") or {}
            v    = s.get("llm_verdict") or ai.get("verdict", "")
            conf = float(s.get("llm_confidence") or ai.get("confidence") or 0)
            if not ip or conf < 0.75:  # seuil de confiance pour prendre le label
                continue
            if v == "true_positive":
                attack_ips.add(ip)
            elif v == "false_positive":
                normal_ips.add(ip)
        if attack_ips or normal_ips:
            log.info(f"Labels LLM : {len(attack_ips)} IPs attaque, {len(normal_ips)} IPs normales")
    except Exception as e:
        log.error(f"Erreur lecture labels LLM: {e}")
    return attack_ips, normal_ips


def _get_human_labeled_ips():
    """
    Lit les labels posés par les analystes SOC via l'interface IA (soc-anomaly-labels).
    Retourne (attack_ips, normal_ips) — labels humains, prioritaires sur LLM.
    """
    attack_ips, normal_ips = set(), set()
    try:
        r = es.search(
            index="soc-anomaly-labels", size=500,
            query={"exists": {"field": "src_ip"}},
            _source=["src_ip", "verdict"],
        )
        for h in r["hits"]["hits"]:
            s  = h["_source"]
            ip = s.get("src_ip", "").strip()
            v  = s.get("verdict", "")
            if not ip or ip == "—":
                continue
            if v == "TP":
                attack_ips.add(ip)
            elif v in ("FP", "Benign"):
                normal_ips.add(ip)
        if attack_ips or normal_ips:
            log.info(f"Labels humains : {len(attack_ips)} IPs attaque, {len(normal_ips)} IPs normales")
    except Exception as e:
        log.error(f"Erreur lecture labels humains: {e}")
    return attack_ips, normal_ips


def build_labeled_dataset(size=5000):
    """
    Génère un dataset labellisé depuis ES :
    - label=1 : IPs dans ATTACK_IPS + IPs validées TP par Ollama + labels humains TP
    - label=0 : logs locaux sans IP attaquante + IPs validées FP par Ollama + labels humains FP
    Labels humains (analystes) sont prioritaires — ils corrigent les erreurs LLM.
    """
    X, y = [], []

    # Fusionner IPs codées en dur + IPs validées par Ollama + labels humains
    llm_attack_ips, llm_normal_ips = _get_llm_labeled_ips()
    human_attack_ips, human_normal_ips = _get_human_labeled_ips()

    # Labels humains FP écrasent les labels LLM TP si conflit
    all_normal_ips = llm_normal_ips | human_normal_ips
    all_attack_ips_extra = (llm_attack_ips | human_attack_ips) - all_normal_ips
    all_attack_ips = list(set(ATTACK_IPS) | all_attack_ips_extra)
    all_attack_ips = [ip for ip in all_attack_ips if ip not in all_normal_ips]
    log.info(f"Dataset IPs attaque : {all_attack_ips}")

    # Logs d'attaque (label=1)
    for ip in all_attack_ips:
        try:
            r = es.search(index="soc-logs-*", size=size // len(ATTACK_IPS),
                query={"bool": {"must": [
                    {"term": {"src_ip": ip}},
                    {"range": {"@timestamp": {"gte": "now-48h"}}}
                ]}},
                _source=["message", "src_ip", "@timestamp", "log_type"]
            )
            for h in r["hits"]["hits"]:
                feat = _log_features(h["_source"])
                X.append(feat)
                y.append(1)
            log.info(f"Dataset attack ({ip}): {len(r['hits']['hits'])} logs")
        except Exception as e:
            log.error(f"Dataset fetch error (attack): {e}")

    # Logs normaux (label=0) — sans IP attaquante
    try:
        r = es.search(index="soc-logs-*", size=size,
            query={"bool": {"must": [
                {"term": {"log_type": "auth"}},
                {"range": {"@timestamp": {"gte": "now-48h"}}}
            ], "must_not": [
                {"terms": {"src_ip": all_attack_ips}}
            ]}},
            _source=["message", "src_ip", "@timestamp"]
        )
        for h in r["hits"]["hits"]:
            src = h["_source"]
            ip = src.get("src_ip", "")
            if ip in all_attack_ips:
                continue
            feat = _log_features(src)
            X.append(feat)
            y.append(0)
        log.info(f"Dataset normal: {len(r['hits']['hits'])} logs")
    except Exception as e:
        log.error(f"Dataset fetch error (normal): {e}")

    # Bonus : logs des IPs validées FP (Ollama + humains) → renforcer la classe normale
    if all_normal_ips:
        try:
            r = es.search(index="soc-logs-*", size=500,
                query={"bool": {"must": [
                    {"terms": {"src_ip": list(all_normal_ips)}},
                    {"range": {"@timestamp": {"gte": "now-48h"}}}
                ]}},
                _source=["message", "src_ip", "@timestamp"]
            )
            fp_count = 0
            for h in r["hits"]["hits"]:
                feat = _log_features(h["_source"])
                X.append(feat)
                y.append(0)
                fp_count += 1
            log.info(f"Dataset FP (LLM+humains): +{fp_count} logs normaux validés")
        except Exception as e:
            log.error(f"Dataset fetch error (FP LLM): {e}")

    return np.array(X), np.array(y)


def train_model():
    log.info("Entraînement Random Forest...")
    X, y = build_labeled_dataset()

    if len(X) == 0 or len(set(y)) < 2:
        log.error("Dataset insuffisant pour l'entraînement")
        return None

    n_attack = int(y.sum())
    n_normal = len(y) - n_attack
    log.info(f"Dataset: {len(y)} logs — {n_attack} attaques, {n_normal} normaux")

    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Évaluation
    y_pred = clf.predict(X_test)
    prec  = precision_score(y_test, y_pred, zero_division=0)
    rec   = recall_score(y_test, y_pred, zero_division=0)
    f1    = f1_score(y_test, y_pred, zero_division=0)
    log.info(f"RF évaluation — Precision={prec:.3f} Recall={rec:.3f} F1={f1:.3f}")
    log.info(f"\n{classification_report(y_test, y_pred, target_names=['Normal','Attaque'], zero_division=0)}")

    # Importance des features
    importances = clf.feature_importances_
    for fname, imp in sorted(zip(FEATURE_COLS, importances), key=lambda x: -x[1]):
        log.info(f"  feature {fname}: {imp:.3f}")

    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": clf, "metrics": {"precision": prec, "recall": rec, "f1": f1},
                     "trained_at": datetime.now(timezone.utc).isoformat()}, f)
    log.info(f"Modèle sauvegardé → {MODEL_PATH}")
    return clf


def load_or_train():
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                data = pickle.load(f)
            clf = data["model"]
            m   = data.get("metrics", {})
            log.info(f"Modèle chargé — F1={m.get('f1','?'):.3f} (entraîné {data.get('trained_at','?')[:10]})")
            return clf
        except Exception:
            pass
    return train_model()


def _dedup(ip):
    key = f"{ip}_{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H')}"
    if key in _seen:
        return True
    _seen[key] = True
    if len(_seen) > 500:
        _seen.clear()
    return False


def run_detection(clf):
    try:
        r = es.search(index="soc-logs-*", size=500,
            query={"bool": {"must": [
                {"range": {"@timestamp": {"gte": f"now-{WINDOW}"}}},
                {"exists": {"field": "src_ip"}}
            ]}},
            _source=["message", "src_ip", "@timestamp", "log_type", "ssh_user", "severity"]
        )
        logs = [h["_source"] for h in r["hits"]["hits"]]
    except Exception as e:
        log.error(f"Fetch error: {e}")
        return

    if not logs:
        log.info("Aucun log avec src_ip — skip")
        return

    # Features + prédictions
    X = np.array([_log_features(l) for l in logs])
    probs = clf.predict_proba(X)[:, 1]

    # Agrégation par IP
    ip_scores = {}
    ip_counts = {}
    ip_samples = {}
    for l, prob in zip(logs, probs):
        ip = l.get("src_ip", "")
        if not ip:
            continue
        if ip not in ip_scores:
            ip_scores[ip] = []
            ip_samples[ip] = l
        ip_scores[ip].append(prob)
        if prob >= THRESHOLD:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    alerts = 0
    for ip, scores in ip_scores.items():
        max_score = float(max(scores))
        attack_count = ip_counts.get(ip, 0)

        if max_score < THRESHOLD or attack_count < MIN_ATTACK_LOGS:
            continue

        severity = "critical" if max_score >= 0.85 else "high" if max_score >= 0.7 else "medium"
        sample   = ip_samples[ip]
        ts       = sample.get("@timestamp", datetime.now(timezone.utc).isoformat())

        log.info(f"RF [{severity.upper()}]: {ip} | score={max_score:.3f} | {attack_count} logs suspects")

        try:
            es.index(index="soc-rf-anomalies", document={
                "@timestamp":     ts,
                "src_ip":         ip,
                "log_type":       sample.get("log_type", "auth"),
                "severity":       severity,
                "alert_type":     "rf",
                "anomaly_score":  round(max_score, 4),
                "attack_logs":    attack_count,
                "total_logs":     len(scores),
            })
        except Exception as e:
            log.error(f"Index error: {e}")

        if not _dedup(ip):
            try:
                requests.post(f"{FLASK_URL}/api/auto_incident", json={
                    "anomaly_score": max_score,
                    "timestamp":     ts,
                    "src_ip":        ip,
                    "log_type":      sample.get("log_type", "auth"),
                    "ssh_user":      sample.get("ssh_user", ""),
                    "severity":      severity,
                    "source":        "rf",
                }, timeout=3)
            except Exception as e:
                log.warning(f"Flask error: {e}")

        alerts += 1

    log.info(f"RF: {alerts} IPs alertes | {len(ip_scores)} IPs vues | {len(logs)} logs analysés")


def _count_llm_labels():
    """Compte le nombre de labels LLM disponibles dans ES."""
    try:
        return es.count(index="soc-incidents", query={"bool": {"must": [
            {"exists": {"field": "llm_verdict"}},
            {"terms": {"llm_verdict.keyword": ["true_positive", "false_positive"]}},
        ]}})["count"]
    except Exception:
        return 0


if __name__ == "__main__":
    import sys
    if "--train-only" in sys.argv:
        clf = train_model()
        sys.exit(0 if clf else 1)

    log.info("Démarré — Random Forest supervisé avec boucle LLM")
    clf = load_or_train()
    if clf is None:
        log.error("Impossible de charger/entraîner le modèle. Arrêt.")
        exit(1)

    _last_train_time = time.time()
    _last_llm_count  = _count_llm_labels()

    while True:
        try:
            run_detection(clf)

            # Ré-entraînement si nouveaux labels LLM ou intervalle écoulé
            now = time.time()
            current_llm_count = _count_llm_labels()
            new_labels = current_llm_count - _last_llm_count
            time_elapsed = now - _last_train_time

            if new_labels >= 3 or (time_elapsed >= RETRAIN_INTERVAL and current_llm_count > 0):
                log.info(f"Ré-entraînement RF : {new_labels} nouveaux labels LLM, {time_elapsed/3600:.1f}h écoulées")
                new_clf = train_model()
                if new_clf is not None:
                    clf = new_clf
                    _last_llm_count  = current_llm_count
                    _last_train_time = now
                    log.info("RF ré-entraîné avec labels Ollama")

        except Exception as e:
            log.error(f"Erreur: {e}")
        time.sleep(DETECT_INTERVAL)
