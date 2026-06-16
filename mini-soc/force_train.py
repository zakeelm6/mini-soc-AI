"""
force_train.py — Force le réentraînement immédiat des deux modèles IA
Usage : python3 force_train.py [--window 25h] [--delete-old]
"""
import os
import sys
import argparse
import joblib
import json
import logging
import numpy as np
from datetime import datetime

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s] %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("force_train")

# Importer les modules de détection
sys.path.insert(0, os.path.dirname(__file__))
from ia_detector import fetch_logs as if_fetch, extract_features as if_features, train_model as if_train
from dl_detector import fetch_logs as dl_fetch, extract_features as dl_features, train_autoencoder as dl_train
from config import ES_HOST, ES_USER, ES_PASSWORD

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--window",      default="25h", help="Fenêtre de baseline (ex: 25h, 48h, 7d)")
    parser.add_argument("--delete-old",  action="store_true", help="Supprimer les anciens modèles avant")
    parser.add_argument("--if-only",     action="store_true", help="Isolation Forest seulement")
    parser.add_argument("--dl-only",     action="store_true", help="Autoencoder seulement")
    args = parser.parse_args()

    MODEL_IF = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")
    MODEL_DL = os.path.join(os.path.dirname(__file__), "autoencoder.pkl")
    MODEL_TH = os.path.join(os.path.dirname(__file__), "autoencoder_threshold.json")

    if args.delete_old:
        for f in [MODEL_IF, MODEL_DL, MODEL_TH]:
            if os.path.exists(f):
                os.remove(f)
                log.info(f"Supprimé : {f}")

    window_start = f"now-{args.window}"
    window_end   = "now"

    log.info(f"Récupération des logs : {window_start} → {window_end}")
    logs = if_fetch(window_start, window_end, size=10000)
    log.info(f"Logs récupérés : {len(logs)}")

    if len(logs) < 50:
        log.error(f"Pas assez de logs ({len(logs)} < 50). Lance d'abord simulate_normal.sh.")
        sys.exit(1)

    # ─── Isolation Forest ───────────────────────────────────────────────────
    if not args.dl_only:
        log.info("=== Entraînement Isolation Forest ===")
        t0 = datetime.now()
        model, cols = if_train(logs)
        elapsed = (datetime.now() - t0).total_seconds()
        if model:
            log.info(f"✓ Isolation Forest entraîné en {elapsed:.1f}s | {len(logs)} logs | {len(cols)} features")
            log.info(f"  Fichier : {MODEL_IF}")
            log.info(f"  Features : {cols}")
        else:
            log.error("✗ Isolation Forest — échec de l'entraînement")

    # ─── Autoencoder ────────────────────────────────────────────────────────
    if not args.if_only:
        log.info("=== Entraînement Autoencoder ===")
        t0 = datetime.now()
        ae, scaler, threshold, cols = dl_train(logs)
        elapsed = (datetime.now() - t0).total_seconds()
        if ae:
            log.info(f"✓ Autoencoder entraîné en {elapsed:.1f}s | {len(logs)} logs | seuil MSE={threshold:.6f}")
            log.info(f"  Fichier : {MODEL_DL}")
            log.info(f"  Seuil threshold : {MODEL_TH}")
        else:
            log.error("✗ Autoencoder — échec de l'entraînement")

    log.info("=== Réentraînement terminé ===")
    log.info("Redémarre les détecteurs pour charger les nouveaux modèles :")
    log.info("  pkill -f ia_detector && pkill -f dl_detector")
    log.info("  python3 ia_detector.py > /tmp/ia.log 2>&1 &")
    log.info("  python3 dl_detector.py > /tmp/dl.log 2>&1 &")

if __name__ == "__main__":
    main()
