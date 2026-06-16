"""
meta_learner.py — Meta-modèle entraîné sur les verdicts llama3

Remplace les poids fixes de l'ensemble (IF×0.30 + RF×0.35 + DL×0.20 + Rate×0.15)
par un modèle qui apprend quelles combinaisons de scores = TP ou FP.

Source de vérité : verdicts llama3 (llm_verdict) dans soc-incidents
Features         : [if_score, rf_score, dl_score, rate_score, votes]
Output           : probabilité TP (0→1)

Usage :
  python3 meta_learner.py --train   # entraîner
  python3 meta_learner.py --stats   # afficher précision par modèle
  import meta_learner; meta_learner.predict(if_s, rf_s, dl_s, rate_s)
"""
import os
import sys
import json
import logging
import joblib
import numpy as np
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from config import ES_HOST, ES_USER, ES_PASSWORD

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s meta_learner — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("meta_learner")

MODEL_PATH  = os.path.join(os.path.dirname(__file__), "meta_model.pkl")
STATS_PATH  = os.path.join(os.path.dirname(__file__), "meta_stats.json")
MIN_SAMPLES = 5    # minimum d'incidents labellisés pour entraîner

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))

# ─── FALLBACK WEIGHTS (si pas encore de meta-model) ──────────────────────────
_FALLBACK_WEIGHTS = dict(w_if=0.30, w_rf=0.35, w_dl=0.20, w_rate=0.15)


# ─── COLLECTE DES DONNÉES D'ENTRAÎNEMENT ─────────────────────────────────────

def _extract_row(s):
    """Extrait le vecteur de features depuis un document ES."""
    if_s   = float(s.get("if_score", 0) or 0)
    rf_s   = float(s.get("rf_score", 0) or 0)
    dl_s   = float(s.get("dl_score", 0) or 0)
    rate   = float(s.get("rate_count", 0) or 0)
    rate_s = min(1.0, rate / 50.0)
    votes  = float(s.get("votes", 0) or 0)
    return [if_s, rf_s, dl_s, rate_s, votes]


def _collect_training_data(size=2000):
    """
    Collecte les données d'entraînement depuis deux sources :

    Source 1 — soc-incidents avec verdict llama3 (vérité terrain haute confiance)
      label : llm_verdict (true_positive=1, false_positive=0), conf >= 0.6

    Source 2 — soc-ensemble-anomalies (pseudo-labels par consensus de votes)
      votes=4 → TP (label=1)
      votes=3 → TP (label=1)
      votes=2 → FP (label=0)  — signal négatif utile

    Les vrais verdicts llama3 ont un poids x2 dans le dataset final.
    """
    X, y = [], []
    n_llm, n_pseudo = 0, 0

    # ── Source 1 : soc-incidents avec llm_verdict ─────────────────────────────
    try:
        r1 = es.search(
            index="soc-incidents", size=size,
            query={"bool": {"must": [
                {"terms": {"llm_verdict.keyword": ["true_positive", "false_positive"]}},
                {"exists": {"field": "if_score"}},
            ]}},
            _source=["if_score","rf_score","dl_score","rate_count","votes",
                     "llm_verdict","llm_confidence"],
        )
        for h in r1["hits"]["hits"]:
            s = h["_source"]
            conf    = float(s.get("llm_confidence") or 0)
            verdict = s.get("llm_verdict", "")
            if conf < 0.6 or verdict not in ("true_positive", "false_positive"):
                continue
            row = _extract_row(s)
            label = 1 if verdict == "true_positive" else 0
            # Dupliquer les vrais verdicts pour leur donner plus de poids
            X.append(row); y.append(label)
            X.append(row); y.append(label)
            n_llm += 1
    except Exception as e:
        log.warning(f"Source 1 (soc-incidents) error: {e}")

    # ── Source 2 : soc-ensemble-anomalies (pseudo-labels par votes) ────────────
    try:
        r2 = es.search(
            index="soc-ensemble-anomalies", size=size,
            query={"bool": {"must": [
                {"exists": {"field": "if_score"}},
                {"exists": {"field": "rf_score"}},
            ]}},
            _source=["if_score","rf_score","dl_score","rate_count","votes"],
        )
        for h in r2["hits"]["hits"]:
            s     = h["_source"]
            votes = int(s.get("votes") or 0)
            if votes == 2:
                label = 0   # 2 modèles concordants → FP probable
            elif votes >= 3:
                label = 1   # 3-4 modèles concordants → TP probable
            else:
                continue
            X.append(_extract_row(s))
            y.append(label)
            n_pseudo += 1
    except Exception as e:
        log.warning(f"Source 2 (soc-ensemble-anomalies) error: {e}")

    if not X:
        return np.array([]), np.array([])

    X_arr, y_arr = np.array(X), np.array(y)
    tp = int(y_arr.sum()); fp = len(y_arr) - tp
    log.info(f"Dataset total : {len(X_arr)} samples "
             f"({n_llm} vrais verdicts llama3 ×2, {n_pseudo} pseudo-labels votes)")
    log.info(f"  TP={tp}  FP={fp}  ratio={tp/len(y_arr):.2f}")
    return X_arr, y_arr


# ─── ENTRAÎNEMENT ────────────────────────────────────────────────────────────

def train():
    """Entraîne le meta-learner sur les verdicts llama3."""
    X, y = _collect_training_data()
    if len(X) < MIN_SAMPLES:
        log.warning(f"Pas assez de données ({len(X)} < {MIN_SAMPLES}) — garder les poids fixes")
        return False

    # Essayer GradientBoosting d'abord, fallback LogisticRegression
    models = {
        "GradientBoosting": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=42))
        ]),
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(C=1.0, max_iter=500, random_state=42))
        ]),
    }

    best_model, best_score, best_name = None, 0, ""
    for name, model in models.items():
        try:
            scores = cross_val_score(model, X, y, cv=min(5, len(X)//2),
                                     scoring="f1", error_score=0)
            mean_f1 = scores.mean()
            log.info(f"  {name}: F1={mean_f1:.3f} (±{scores.std():.3f})")
            if mean_f1 > best_score:
                best_score, best_model, best_name = mean_f1, model, name
        except Exception as e:
            log.warning(f"  {name} failed: {e}")

    if best_model is None:
        return False

    best_model.fit(X, y)
    joblib.dump(best_model, MODEL_PATH)
    log.info(f"Meta-model sauvegardé : {best_name} F1={best_score:.3f}")

    # Calculer la précision par modèle individuel vs meta-learner
    _compute_and_save_stats(X, y, best_model, best_score)
    return True


# ─── STATISTIQUES PAR MODÈLE ─────────────────────────────────────────────────

def _compute_and_save_stats(X, y, meta_model, meta_f1):
    """
    Compare la précision de chaque modèle individuel vs le meta-learner.
    Montre quels modèles sont les plus fiables sur nos données.
    """
    from sklearn.metrics import precision_score, recall_score, f1_score

    n = len(y)
    stats = {"computed_at": datetime.now(timezone.utc).isoformat(), "n_samples": n}

    # Seuils de décision pour chaque modèle individuel
    thresholds = {
        "IF":   (0, 0.25),   # colonne 0
        "RF":   (1, 0.55),   # colonne 1
        "DL":   (2, 0.30),   # colonne 2
        "Rate": (3, 0.20),   # colonne 3
    }

    model_stats = {}
    for name, (col, thresh) in thresholds.items():
        preds = (X[:, col] >= thresh).astype(int)
        if preds.sum() == 0:
            model_stats[name] = {"precision": 0, "recall": 0, "f1": 0}
            continue
        model_stats[name] = {
            "precision": round(float(precision_score(y, preds, zero_division=0)), 3),
            "recall":    round(float(recall_score(y, preds, zero_division=0)), 3),
            "f1":        round(float(f1_score(y, preds, zero_division=0)), 3),
        }
        log.info(f"  {name:5s} → precision={model_stats[name]['precision']:.3f} "
                 f"recall={model_stats[name]['recall']:.3f} f1={model_stats[name]['f1']:.3f}")

    # Meta-learner
    meta_preds = meta_model.predict(X)
    model_stats["Meta"] = {
        "precision": round(float(precision_score(y, meta_preds, zero_division=0)), 3),
        "recall":    round(float(recall_score(y, meta_preds, zero_division=0)), 3),
        "f1":        round(float(meta_f1), 3),
    }
    log.info(f"  Meta → precision={model_stats['Meta']['precision']:.3f} "
             f"recall={model_stats['Meta']['recall']:.3f} f1={model_stats['Meta']['f1']:.3f}")

    # Poids dynamiques dérivés des F1 scores
    total_f1 = sum(v["f1"] for k, v in model_stats.items() if k != "Meta") or 1
    dynamic_weights = {
        "w_if":   round(model_stats["IF"]["f1"] / total_f1, 3),
        "w_rf":   round(model_stats["RF"]["f1"] / total_f1, 3),
        "w_dl":   round(model_stats["DL"]["f1"] / total_f1, 3),
        "w_rate": round(model_stats["Rate"]["f1"] / total_f1, 3),
    }
    log.info(f"  Poids dynamiques : {dynamic_weights}")

    stats["models"]          = model_stats
    stats["dynamic_weights"] = dynamic_weights
    stats["meta_f1"]         = round(float(meta_f1), 3)
    stats["model_path"]      = MODEL_PATH

    with open(STATS_PATH, "w") as f:
        json.dump(stats, f, indent=2)
    log.info(f"Stats sauvegardées → {STATS_PATH}")
    return stats


# ─── PRÉDICTION ──────────────────────────────────────────────────────────────

def load_model():
    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


def predict(if_s, rf_s, dl_s, rate_count, votes=2):
    """
    Prédit la probabilité TP avec le meta-model (ou poids fixes en fallback).
    Retourne (score_final, source) où source = "meta" ou "fallback".
    """
    model = load_model()
    rate_s = min(1.0, float(rate_count) / 50.0)

    if model is not None:
        try:
            X = np.array([[float(if_s), float(rf_s), float(dl_s), rate_s, float(votes)]])
            proba = model.predict_proba(X)[0][1]   # probabilité classe TP
            return round(float(proba), 4), "meta"
        except Exception as e:
            log.warning(f"Meta predict error: {e}")

    # Fallback poids fixes
    w = _FALLBACK_WEIGHTS
    score = w["w_if"]*float(if_s) + w["w_rf"]*float(rf_s) + \
            w["w_dl"]*float(dl_s) + w["w_rate"]*rate_s
    return round(min(1.0, float(score)), 4), "fallback"


def load_stats():
    try:
        with open(STATS_PATH) as f:
            return json.load(f)
    except Exception:
        return None


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if "--train" in sys.argv:
        ok = train()
        print("Entraînement réussi ✓" if ok else "Pas assez de données pour entraîner")

    elif "--stats" in sys.argv:
        stats = load_stats()
        if not stats:
            print("Aucune stats — lancer --train d'abord")
        else:
            print(f"\nMeta-learner stats ({stats['n_samples']} incidents)")
            print(f"{'Modèle':8} {'Precision':>10} {'Recall':>8} {'F1':>8}")
            print("-" * 40)
            for name, s in stats["models"].items():
                marker = " ←" if name == "Meta" else ""
                print(f"{name:8} {s['precision']:>10.3f} {s['recall']:>8.3f} {s['f1']:>8.3f}{marker}")
            print(f"\nPoids dynamiques : {stats['dynamic_weights']}")

    elif "--predict" in sys.argv:
        # Test : python3 meta_learner.py --predict 0.8 0.9 0.2 30
        args = [float(x) for x in sys.argv[2:6]]
        if len(args) >= 4:
            score, src = predict(*args)
            print(f"Score: {score:.4f} (source: {src})")
    else:
        print("Usage: meta_learner.py --train | --stats | --predict IF RF DL RATE")
