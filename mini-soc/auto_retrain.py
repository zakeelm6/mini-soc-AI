#!/usr/bin/env python3
"""
auto_retrain.py — Réentraînement automatique après réception de logs d'attaque

Attend que MIN_LOGS logs arrivent depuis l'IP cible, puis :
  1. Réentraîne Isolation Forest + Autoencoder (force_train.py)
  2. Redémarre ia_detector avec les nouveaux modèles
  3. Attend que les anomalies IA soient générées
  4. Réentraîne le meta-learner

Usage : python3 auto_retrain.py 192.168.50.20 [--min-logs 200] [--window 2h]
"""
import os, sys, time, subprocess, argparse, logging
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(__file__))
from config import ES_HOST, ES_USER, ES_PASSWORD
from elasticsearch import Elasticsearch
import meta_learner

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))
logging.basicConfig(level=logging.INFO,
    format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger()

SOC_DIR = os.path.dirname(os.path.abspath(__file__))
VENV    = os.path.join(SOC_DIR, "venv", "bin", "python3")

R  = "\033[1;31m"; Y = "\033[1;33m"; G = "\033[0;32m"
B  = "\033[0;34m"; W = "\033[1;37m"; NC = "\033[0m"


def count_logs(ip, since_minutes=120):
    since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    try:
        r = es.search(index="soc-logs-*", size=0,
            query={"bool": {"must": [
                {"term": {"src_ip.keyword": ip}},
                {"range": {"@timestamp": {"gte": since}}},
            ]}})
        return r["hits"]["total"]["value"]
    except:
        return 0


def count_anomalies(ip, since_minutes=60):
    since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    try:
        r = es.search(index="soc-ensemble-anomalies", size=0,
            query={"bool": {"must": [
                {"term": {"src_ip.keyword": ip}},
                {"range": {"@timestamp": {"gte": since}}},
            ]}})
        return r["hits"]["total"]["value"]
    except:
        return 0


def run(cmd, label):
    print(f"\n  {B}→ {label}{NC}")
    result = subprocess.run(cmd, cwd=SOC_DIR, capture_output=False)
    return result.returncode == 0


def retrain_ia(window):
    """Réentraîne IF + Autoencoder avec les logs récents."""
    print(f"\n{W}{'─'*55}{NC}")
    print(f"  {Y}⟳  RÉENTRAÎNEMENT IA (Isolation Forest + Autoencoder){NC}")
    print(f"{W}{'─'*55}{NC}")
    ok = run(
        [VENV, "force_train.py", f"--window", window],
        f"force_train.py --window {window}"
    )
    if ok:
        print(f"  {G}✓ Modèles IA réentraînés{NC}")
    else:
        print(f"  {R}✗ Échec force_train — vérifier les logs{NC}")
    return ok


def restart_detectors():
    """Redémarre ia_detector pour charger les nouveaux modèles."""
    print(f"\n  {B}→ Redémarrage ia_detector...{NC}")
    subprocess.run(["pkill", "-f", "ia_detector"], capture_output=True)
    time.sleep(1)
    subprocess.Popen(
        [VENV, "-u", os.path.join(SOC_DIR, "ia_detector.py")],
        stdout=open("/tmp/ia.log", "w"), stderr=subprocess.STDOUT
    )
    print(f"  {G}✓ ia_detector redémarré{NC}")


def retrain_meta():
    """Réentraîne le meta-learner sur les nouvelles anomalies."""
    print(f"\n{W}{'─'*55}{NC}")
    print(f"  {Y}⟳  RÉENTRAÎNEMENT META-LEARNER{NC}")
    print(f"{W}{'─'*55}{NC}")
    ok = meta_learner.train()
    if ok:
        stats = meta_learner.load_stats()
        if stats:
            print(f"  {G}✓ Meta-learner réentraîné{NC}")
            print(f"  Samples : {stats['n_samples']}  |  F1 = {stats['meta_f1']:.3f}")
            print(f"  Poids dynamiques : {stats['dynamic_weights']}")
    else:
        print(f"  {R}✗ Pas assez de données pour le meta-learner{NC}")
    return ok


def watch_and_train(ip, min_logs, window):
    print(f"\n{W}{'═'*55}{NC}")
    print(f"  {R}⚡  AUTO-RÉENTRAÎNEMENT APRÈS ATTAQUE{NC}")
    print(f"  IP cible   : {Y}{ip}{NC}")
    print(f"  Seuil logs : {min_logs}")
    print(f"  Fenêtre    : {window}")
    print(f"{W}{'═'*55}{NC}\n")

    # ── Phase 1 : attendre les logs ────────────────────────────────────────────
    print(f"  {B}[Phase 1]{NC} En attente de logs depuis {ip}...")
    while True:
        n = count_logs(ip)
        bar = "█" * min(20, n * 20 // max(min_logs, 1))
        bar_empty = "░" * (20 - len(bar))
        pct = min(100, n * 100 // max(min_logs, 1))
        print(f"\r  [{bar}{bar_empty}] {n}/{min_logs} logs ({pct}%)  ", end="", flush=True)
        if n >= min_logs:
            print(f"\n  {G}✓ {n} logs reçus — lancement du réentraînement{NC}")
            break
        time.sleep(5)

    # ── Phase 2 : réentraîner IF + DL ─────────────────────────────────────────
    retrain_ia(window)

    # ── Phase 3 : redémarrer les détecteurs ────────────────────────────────────
    restart_detectors()

    # ── Phase 4 : attendre les anomalies IA ───────────────────────────────────
    print(f"\n  {B}[Phase 4]{NC} Attente des anomalies IA (max 3min)...")
    deadline = time.time() + 180
    while time.time() < deadline:
        n_anom = count_anomalies(ip)
        print(f"\r  Anomalies détectées : {n_anom}  ", end="", flush=True)
        if n_anom >= 5:
            print(f"\n  {G}✓ {n_anom} anomalies IA générées{NC}")
            break
        time.sleep(8)
    else:
        print(f"\n  {Y}⚠ Timeout — réentraînement meta avec données existantes{NC}")

    # ── Phase 5 : meta-learner ─────────────────────────────────────────────────
    retrain_meta()

    print(f"\n{W}{'═'*55}{NC}")
    print(f"  {G}✓  Réentraînement complet terminé{NC}")
    print(f"  {W}Résumé :{NC}")
    print(f"    Logs d'attaque capturés : {count_logs(ip)}")
    print(f"    Anomalies IA générées   : {count_anomalies(ip)}")
    stats = meta_learner.load_stats()
    if stats:
        print(f"    Meta-learner F1         : {stats['meta_f1']:.3f}")
        print(f"    Poids dynamiques        : {stats['dynamic_weights']}")
    print(f"{W}{'═'*55}{NC}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip",          nargs="?", default="192.168.50.20")
    parser.add_argument("--min-logs",  type=int,  default=200)
    parser.add_argument("--window",    default="2h")
    args = parser.parse_args()
    try:
        watch_and_train(args.ip, args.min_logs, args.window)
    except KeyboardInterrupt:
        print(f"\n  {Y}Interrompu.{NC}")
