from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response, session, g, Response
from elasticsearch import Elasticsearch
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import subprocess
import threading
import hashlib
import logging
log = logging.getLogger("soc")
import bcrypt
import pyotp
import qrcode
import base64
import secrets
import uuid
import json
import os
import csv
import io
import requests as _requests
from fpdf import FPDF
from dotenv import load_dotenv
load_dotenv()
from config import ES_HOST, ES_USER, ES_PASSWORD
from llm_analyzer import analyze_incident
import notifier

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(hours=8)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

@app.template_filter('local_ts')
def local_ts_filter(ts, fmt="%Y-%m-%d %H:%M"):
    """Convertit un timestamp UTC ISO en UTC+1 pour affichage."""
    if not ts:
        return '—'
    try:
        from datetime import timezone as _tz
        dt = datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
        dt_local = dt.astimezone(_tz(timedelta(hours=1)))
        return dt_local.strftime(fmt)
    except Exception:
        return str(ts)[:16].replace('T', ' ')

# ─── AUTH ────────────────────────────────────────────────────────────────────

USERS_PATH  = os.path.join(os.path.dirname(__file__), "users.json")
LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3, "Manager": 4}

def _load_users():
    try:
        with open(USERS_PATH) as f:
            return json.load(f)
    except:
        return {}

def _save_users(users):
    with open(USERS_PATH, "w") as f:
        json.dump(users, f, indent=2)

def _hash(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def _check_password(pw, stored):
    # Support migration: bcrypt hashes start with $2b$, legacy are SHA256 hex
    if stored.startswith("$2b$"):
        return bcrypt.checkpw(pw.encode(), stored.encode())
    return hashlib.sha256(pw.encode()).hexdigest() == stored

def get_current_user():
    username = session.get("username")
    if not username:
        return None
    users = _load_users()
    u = users.get(username)
    if u and u.get("active", True):
        return {"username": username, **u}
    return None

@app.context_processor
def inject_current_user():
    return {"current_user": get_current_user()}

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("login_page", next=request.path))
        return f(*args, **kwargs)
    return wrapper

def require_level(min_level):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("login_page", next=request.path))
            if LEVEL_ORDER.get(user["level"], 0) < LEVEL_ORDER.get(min_level, 0):
                return render_template("403.html", user=user), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

def compute_priority_score(severity, score, created_at, llm_confidence=None):
    """
    Score de priorité composite : sévérité + score IA + âge de l'incident.
    Plus le score est élevé, plus l'incident doit être traité en premier.

    Formule :
      priority = sev_weight(40%) + ia_score(35%) + age_urgency(25%)
      + bonus confiance llama3 si disponible
    """
    SEV_WEIGHTS = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1}
    sev_w = SEV_WEIGHTS.get(severity, 0.3)

    ia_w = min(1.0, float(score) / 10.0) if score else 0.0

    # Âge : plus c'est vieux, plus c'est urgent (max à 4h = 1.0)
    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        age_min = (datetime.now(timezone.utc) - created).total_seconds() / 60
        age_w = min(1.0, age_min / 240)   # 240 min = 4h → urgence max
    except Exception:
        age_w = 0.0

    priority = 0.40 * sev_w + 0.35 * ia_w + 0.25 * age_w

    # Bonus llama3 : si confiance élevée → booste la priorité
    if llm_confidence and float(llm_confidence) >= 0.80:
        priority = min(1.0, priority + 0.05)

    return round(priority, 4)


def auto_assign(severity, score=0, created_at=None, llm_confidence=None):
    """
    Assigne l'incident à l'analyste optimal selon :
    1. Niveau requis (sévérité)
    2. Charge actuelle (nb incidents ouverts)
    3. Score de priorité de l'incident (sévérité + score IA + âge)
    L'analyste le moins chargé reçoit les incidents les plus prioritaires.
    """
    users = _load_users()
    if severity == "critical":
        target_level = "L3"
    elif severity == "high":
        target_level = "L2"
    else:
        target_level = "L1"
    candidates = [u for u, d in users.items() if d.get("level") == target_level and d.get("active", True)]
    if not candidates:
        candidates = [u for u, d in users.items() if d.get("active", True) and d.get("level") != "L3"]
    if not candidates:
        return None, "L1"
    try:
        # Charge actuelle par analyste (incidents ouverts)
        r = es.search(index="soc-incidents", size=0,
            query={"bool": {"should": [
                {"term": {"status.keyword": "awaiting_action"}},
                {"term": {"status.keyword": "in_progress"}},
            ], "minimum_should_match": 1}},
            aggs={"by_assignee": {"terms": {"field": "assigned_to.keyword", "size": 20},
                                  "aggs": {"critical_count": {"filter": {"term": {"severity": "critical"}}}}}}
        )
        counts  = {}
        crit_counts = {}
        for b in r["aggregations"]["by_assignee"]["buckets"]:
            name = b["key"]
            counts[name]      = b["doc_count"]
            crit_counts[name] = b["critical_count"]["doc_count"]

        # Score de charge : pénalise ceux qui ont déjà beaucoup de critiques
        def load_score(u):
            name = users[u]["name"]
            total = counts.get(name, 0)
            crits = crit_counts.get(name, 0)
            return total + crits * 2   # incidents critiques comptent double

        best = min(candidates, key=load_score)
        return users[best]["name"], target_level
    except Exception:
        return users[candidates[0]]["name"] if candidates else None, target_level

# ─── VM CONFIG (persisté dans vm_config.json) ───────────────────────────────
VM_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "vm_config.json")
VM_ROLES = {
    "SOC":       {"icon": "fas fa-shield-alt",      "color": "var(--blue)",   "tools": "Elasticsearch · Logstash · Kibana · Flask · IA"},
    "Victime":   {"icon": "fas fa-server",           "color": "var(--orange)", "tools": "Apache · DVWA · SSH · Filebeat · Suricata"},
    "Attaquant": {"icon": "fas fa-skull-crossbones", "color": "var(--red)",    "tools": "Hydra · Nmap · Nikto · SQLMap"},
    "Autre":     {"icon": "fas fa-question-circle",  "color": "var(--muted)",  "tools": ""},
}

def load_vm_config():
    try:
        with open(VM_CONFIG_PATH) as f:
            return json.load(f)
    except:
        return {}

def save_vm_config(cfg):
    with open(VM_CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
INCIDENT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "incident_config.json")

def load_incident_config():
    try:
        with open(INCIDENT_CONFIG_PATH) as f:
            return json.load(f)
    except:
        return {"enabled": True, "min_score": 2.0, "max_score": 10.0}

def save_incident_config(cfg):
    with open(INCIDENT_CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

auto_incident_seen = set()

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))

# ─── AUDIT TRAIL ─────────────────────────────────────────────────────────────

def push_notif(recipient, message, notif_type="info", incident_id=None, severity=None):
    """
    Crée une notification in-app pour un utilisateur.
    Stockée dans soc-notifications (ES).
    Types : info | warning | critical | success
    """
    try:
        es.index(index="soc-notifications", document={
            "@timestamp":  datetime.now(timezone.utc).isoformat(),
            "recipient":   recipient,   # username cible (ou "all" pour tous)
            "message":     message,
            "type":        notif_type,
            "incident_id": incident_id,
            "severity":    severity,
            "read":        False,
        })
    except Exception:
        pass


def audit_log(action, username=None, details=None, level=None):
    """Write a security audit event to soc-audit-log ES index."""
    try:
        es.index(index="soc-audit-log", document={
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "action":     action,
            "username":   username or session.get("username", "system"),
            "level":      level,
            "ip":         request.remote_addr if request else None,
            "details":    details or {},
        })
    except Exception:
        pass

KIBANA_DASHBOARD = "http://192.168.50.10:5601/app/dashboards#/view/06359277-a130-4b6a-a62c-477eb5d8e672"
KIBANA_DISCOVER  = "http://192.168.50.10:5601/app/discover"

ENRICHMENT = {
    "ssh_bruteforce": {
        "explanation": "Tentatives répétées de connexion SSH — attaque par force brute.",
        "actions": ["Bloquer l'IP : sudo iptables -A INPUT -s <IP> -j DROP", "Vérifier /var/log/auth.log", "Configurer fail2ban"]
    },
    "ia_anomaly": {
        "explanation": "Isolation Forest a détecté un comportement anormal.",
        "actions": ["Analyser dans Kibana Discover", "Corréler avec alertes Suricata", "Vérifier faux positif ou vrai incident"]
    },
    "suricata_ids": {
        "explanation": "Suricata a détecté une signature d'attaque connue.",
        "actions": ["Bloquer l'IP source", "Identifier le type d'attaque", "Inspecter les machines cibles"]
    },
    "cve_critical": {
        "explanation": "Vulnérabilité critique (CVSS >= 9.0) publiée.",
        "actions": ["Vérifier si le composant est installé", "Appliquer le patch", "Surveiller les tentatives d'exploitation"]
    }
}

# ─── HELPERS ────────────────────────────────────────────────────────────────

def get_tailscale_status():
    try:
        out = subprocess.run(["tailscale", "status"], capture_output=True, text=True, timeout=5).stdout
        machines = []
        for line in out.strip().splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                machines.append({
                    "ip": parts[0],
                    "hostname": parts[1],
                    "user": parts[2],
                    "os": parts[3],
                    "online": "offline" not in line
                })
        return machines
    except:
        return []

def es_count(index, query=None):
    try:
        q = query or {"match_all": {}}
        return es.count(index=index, query=q)["count"]
    except:
        return 0

def es_search(index, query=None, size=50, sort=None):
    try:
        q = query or {"match_all": {}}
        s = sort or [{"@timestamp": {"order": "desc"}}]
        r = es.search(index=index, query=q, size=size, sort=s)
        return [h["_source"] for h in r["hits"]["hits"]]
    except:
        return []

def es_search_with_id(index, query=None, size=50, sort=None):
    """Same as es_search but includes _id in each result."""
    try:
        q = query or {"match_all": {}}
        s = sort or [{"@timestamp": {"order": "desc"}}]
        r = es.search(index=index, query=q, size=size, sort=s)
        results = []
        for h in r["hits"]["hits"]:
            doc = h["_source"].copy()
            doc["_id"] = h["_id"]
            results.append(doc)
        return results
    except:
        return []

# ─── PAGES ──────────────────────────────────────────────────────────────────

def compute_risk_score(ssh_failed, ia_critical, cve_critical):
    return min(10.0, round(
        (min(ssh_failed, 500)  / 500)  * 3 +
        (min(ia_critical, 100) / 100)  * 4 +
        (min(cve_critical, 10) / 10)   * 3
    , 1))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login_page():
    if get_current_user():
        return redirect(url_for("home"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        totp_code = request.form.get("totp_code", "").strip()
        users = _load_users()
        u = users.get(username)
        if u and u.get("active", True) and _check_password(password, u.get("password", "")):
            # Migrate legacy SHA256 hash to bcrypt on first successful login
            if not u["password"].startswith("$2b$"):
                u["password"] = _hash(password)
                users[username] = u
                _save_users(users)
            # MFA check for L2/L3 — only if TOTP is configured
            totp_secret = u.get("totp_secret")
            if totp_secret:
                if not totp_code or not pyotp.TOTP(totp_secret).verify(totp_code, valid_window=1):
                    audit_log("login_mfa_fail", username=username, details={"reason": "invalid_totp"}, level=u.get("level"))
                    return render_template("login.html", error="Code MFA invalide.", need_totp=True, username=username)
            session["username"] = username
            session.permanent = True
            audit_log("login", username=username, details={"method": "password+mfa" if totp_secret else "password"}, level=u.get("level"))
            next_url = request.args.get("next") or url_for("home")
            return redirect(next_url)
        audit_log("login_fail", username=username, details={"reason": "bad_credentials"})
        error = "Identifiants incorrects."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    audit_log("logout")
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@require_auth
def home():
    total_logs      = es_count("soc-logs*")
    total_anomalies = es_count("soc-anomalies")
    total_cve       = es_count("soc-cve-alerts")
    ssh_failed      = es_count("soc-logs*", {"term": {"tags": "ssh_failed"}})
    ia_critical     = es_count("soc-anomalies", {"range": {"anomaly_score": {"gte": 0.7}}})
    cve_critical    = es_count("soc-cve-alerts", {"range": {"cvss_score": {"gte": 7.0}}})
    risk_score      = compute_risk_score(ssh_failed, ia_critical, cve_critical)
    if risk_score >= 7:
        risk_level, risk_color = "CRITIQUE", "var(--red)"
    elif risk_score >= 4:
        risk_level, risk_color = "ÉLEVÉ", "var(--orange)"
    elif risk_score >= 2:
        risk_level, risk_color = "MODÉRÉ", "var(--yellow)"
    else:
        risk_level, risk_color = "FAIBLE", "var(--green)"
    tailscale    = get_tailscale_status()
    online_count = sum(1 for m in tailscale if m["online"])
    recent_alerts = es_search("soc-flask-alerts", size=10,
                              sort=[{"timestamp": {"order": "desc"}}])
    return render_template("home.html",
        alerts=recent_alerts,
        total_logs=total_logs,
        total_anomalies=total_anomalies,
        total_cve=total_cve,
        ssh_failed=ssh_failed,
        tailscale=tailscale,
        online_count=online_count,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_color=risk_color,
        kibana_url=KIBANA_DASHBOARD,
        kibana_discover=KIBANA_DISCOVER
    )

@app.route("/logs")
@require_auth
def logs_page():
    return render_template("logs.html")

@app.route("/ia")
@require_level("L2")
def ia_page():
    return render_template("ia.html")


@app.route("/ensemble")
@require_level("L2")
def ensemble_page():
    return render_template("ensemble.html", current_user=get_current_user())


@app.route("/api/ensemble/dashboard")
@require_level("L2")
def api_ensemble_dashboard():
    """Agrège les votes des 4 modèles ML par IP + décision finale ensemble."""
    try:
        window = request.args.get("window", "24h")
        size   = int(request.args.get("size", 50))

        def fetch(index, score_field):
            try:
                r = es.search(index=index, size=500,
                    query={"range": {"@timestamp": {"gte": f"now-{window}"}}},
                    sort=[{"@timestamp": {"order": "desc"}}])
                out = {}
                for h in r["hits"]["hits"]:
                    s   = h["_source"]
                    ip  = s.get("src_ip", "unknown")
                    sc  = float(s.get(score_field, 0) or 0)
                    sev = s.get("severity", "low")
                    ts  = s.get("@timestamp", "")
                    if ip not in out or sc > out[ip]["score"]:
                        out[ip] = {"score": round(sc, 3), "severity": sev, "ts": ts, "count": 0}
                    out[ip]["count"] = out[ip].get("count", 0) + 1
                return out
            except Exception:
                return {}

        if_data   = fetch("soc-anomalies",    "anomaly_score")
        dl_data   = fetch("soc-dl-anomalies", "anomaly_score")
        rf_data   = fetch("soc-rf-anomalies", "anomaly_score")

        # Rate detector → incidents créés directement
        rate_data = {}
        try:
            r = es.search(index="soc-incidents", size=200,
                query={"bool": {"must": [
                    {"term": {"type": "rate_anomaly"}},
                    {"range": {"@timestamp": {"gte": f"now-{window}"}}}
                ]}})
            for h in r["hits"]["hits"]:
                s  = h["_source"]
                ip = s.get("src_ip", s.get("ip", "unknown"))
                sc = float(s.get("anomaly_score", 0.9))
                if ip not in rate_data or sc > rate_data[ip]["score"]:
                    rate_data[ip] = {"score": round(sc, 3), "severity": s.get("severity","high"), "ts": s.get("@timestamp",""), "count": 1}
        except Exception:
            pass

        # Merge all IPs
        all_ips = set(if_data) | set(dl_data) | set(rf_data) | set(rate_data)

        SEV_W = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
        rows  = []
        for ip in all_ips:
            v_if   = if_data.get(ip,   {}).get("score", 0.0)
            v_dl   = dl_data.get(ip,   {}).get("score", 0.0)
            v_rf   = rf_data.get(ip,   {}).get("score", 0.0)
            v_rate = rate_data.get(ip, {}).get("score", 0.0)

            # Weighted vote: RF 40%, IF 25%, DL 25%, Rate 10%
            ensemble_score = round(v_rf * 0.4 + v_if * 0.25 + v_dl * 0.25 + v_rate * 0.10, 3)

            if   ensemble_score >= 0.80: sev = "critical"
            elif ensemble_score >= 0.60: sev = "high"
            elif ensemble_score >= 0.35: sev = "medium"
            else:                        sev = "low"

            votes = sum(1 for v in [v_if, v_dl, v_rf, v_rate] if v > 0)
            ts_candidates = [
                if_data.get(ip, {}).get("ts", ""),
                dl_data.get(ip, {}).get("ts", ""),
                rf_data.get(ip, {}).get("ts", ""),
                rate_data.get(ip, {}).get("ts", ""),
            ]
            last_seen = max((t for t in ts_candidates if t), default="")

            rows.append({
                "ip": ip,
                "votes": {"if": v_if, "dl": v_dl, "rf": v_rf, "rate": v_rate},
                "ensemble_score": ensemble_score,
                "severity": sev,
                "model_count": votes,
                "last_seen": last_seen,
                "counts": {
                    "if":   if_data.get(ip,   {}).get("count", 0),
                    "dl":   dl_data.get(ip,   {}).get("count", 0),
                    "rf":   rf_data.get(ip,   {}).get("count", 0),
                    "rate": rate_data.get(ip, {}).get("count", 0),
                }
            })

        rows.sort(key=lambda x: x["ensemble_score"], reverse=True)

        # Stats globales
        stats = {
            "total_ips": len(rows),
            "critical":  sum(1 for r in rows if r["severity"] == "critical"),
            "high":      sum(1 for r in rows if r["severity"] == "high"),
            "medium":    sum(1 for r in rows if r["severity"] == "medium"),
            "low":       sum(1 for r in rows if r["severity"] == "low"),
            "models": {
                "if":   {"active": bool(if_data),   "detections": len(if_data)},
                "dl":   {"active": bool(dl_data),   "detections": len(dl_data)},
                "rf":   {"active": bool(rf_data),   "detections": len(rf_data)},
                "rate": {"active": bool(rate_data), "detections": len(rate_data)},
            }
        }

        return jsonify({"rows": rows[:size], "stats": stats, "window": window})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ensemble/model_stats")
@require_level("L2")
def api_ensemble_model_stats():
    """Retourne les métriques des modèles + SHAP feature importance."""
    import json as _json
    result = {}

    # Meta-learner stats
    meta_stats_path = os.path.join(os.path.dirname(__file__), "meta_stats.json")
    try:
        with open(meta_stats_path) as f:
            result["meta"] = _json.load(f)
    except Exception:
        result["meta"] = None

    # SHAP values (XGBoost RF)
    shap_path = os.path.join(os.path.dirname(__file__), "shap_values.json")
    try:
        with open(shap_path) as f:
            result["shap"] = _json.load(f)
    except Exception:
        result["shap"] = None

    # RF/XGBoost model metrics
    rf_path = os.path.join(os.path.dirname(__file__), "rf_model.pkl")
    try:
        import pickle
        with open(rf_path, "rb") as f:
            rf_data = pickle.load(f)
        def _to_float(v):
            try: return float(v)
            except: return v
        metrics = {k: _to_float(v) for k, v in rf_data.get("metrics", {}).items()}
        fi = {k: _to_float(v) for k, v in rf_data.get("feature_importance", {}).items()}
        result["xgboost"] = {
            "metrics": metrics,
            "model_type": rf_data.get("model_type", "random_forest"),
            "trained_at": rf_data.get("trained_at", ""),
            "feature_importance": fi
        }
    except Exception:
        result["xgboost"] = None

    return jsonify(result)


# ─── INVESTIGATION ────────────────────────────────────────────────────────────

@app.route("/investigation")
@require_level("L1")
def investigation_page():
    return render_template("investigation.html")

@app.route("/api/investigation/list")
@require_level("L1")
def api_investigation_list():
    try:
        status  = request.args.get("status", "")
        sev     = request.args.get("severity", "")
        size    = int(request.args.get("size", 100))
        must = []
        if status:  must.append({"term": {"status": status}})
        if sev:     must.append({"term": {"severity": sev}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        r = es.search(index="soc-investigations", size=size,
                      query=query,
                      sort=[{"created_at": {"order": "desc"}}])
        items = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            s["_id"] = h["_id"]
            items.append(s)
        total = r["hits"]["total"]["value"]
        # counts per status
        agg = es.search(index="soc-investigations", size=0,
                        aggs={"by_status": {"terms": {"field": "status", "size": 10}},
                              "by_sev": {"terms": {"field": "severity", "size": 10}}})
        by_status = {b["key"]: b["doc_count"] for b in agg["aggregations"]["by_status"]["buckets"]}
        by_sev    = {b["key"]: b["doc_count"] for b in agg["aggregations"]["by_sev"]["buckets"]}
        return jsonify({"items": items, "total": total, "by_status": by_status, "by_sev": by_sev})
    except Exception as e:
        return jsonify({"items": [], "total": 0, "by_status": {}, "by_sev": {}, "error": str(e)})

@app.route("/api/investigation/create", methods=["POST"])
@require_level("L2")
def api_investigation_create():
    """Envoie une détection ensemble en investigation."""
    data = request.json or {}
    ip   = data.get("ip", "")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    # Check dedup
    existing = es.search(index="soc-investigations", size=1,
        query={"bool": {"must": [
            {"term": {"ip": ip}},
            {"terms": {"status": ["new", "analyzing", "confirmed"]}}
        ]}})
    if existing["hits"]["total"]["value"] > 0:
        return jsonify({"status": "already_exists", "id": existing["hits"]["hits"][0]["_id"]}), 200
    doc = {
        "inv_id":        str(uuid.uuid4())[:8].upper(),
        "ip":            ip,
        "ensemble_score": float(data.get("ensemble_score", 0)),
        "severity":      data.get("severity", "medium"),
        "votes":         data.get("votes", {}),
        "counts":        data.get("counts", {}),
        "model_count":   int(data.get("model_count", 0)),
        "last_seen":     data.get("last_seen", ""),
        "status":        "new",
        "assigned_to":   "",
        "notes":         [],
        "llm_verdict":   None,
        "llm_summary":   None,
        "llm_confidence": None,
        "incident_id":   None,
        "created_at":    datetime.utcnow().isoformat() + "Z",
        "updated_at":    datetime.utcnow().isoformat() + "Z",
        "created_by":    session.get("username", "system"),
        "source":        "ensemble",
    }
    result = es.index(index="soc-investigations", document=doc)
    doc["_id"] = result["_id"]
    return jsonify({"status": "created", "id": result["_id"], "inv_id": doc["inv_id"]}), 201

@app.route("/api/investigation/<inv_es_id>/update", methods=["POST"])
@require_level("L1")
def api_investigation_update(inv_es_id):
    data = request.json or {}
    update = {"updated_at": datetime.utcnow().isoformat() + "Z"}
    for field in ("status", "assigned_to", "severity"):
        if field in data:
            update[field] = data[field]
    if "note" in data and data["note"].strip():
        user = session.get("username", "?")
        note = {"text": data["note"], "by": user, "at": datetime.utcnow().isoformat() + "Z"}
        es.update(index="soc-investigations", id=inv_es_id,
                  body={"script": {"source": "ctx._source.notes.add(params.note)", "params": {"note": note}}})
    if update:
        es.update(index="soc-investigations", id=inv_es_id, body={"doc": update})
    return jsonify({"status": "ok"})

@app.route("/api/investigation/<inv_es_id>/analyze", methods=["POST"])
@require_level("L2")
def api_investigation_analyze(inv_es_id):
    """Lance analyse Ollama sur une investigation."""
    try:
        r = es.get(index="soc-investigations", id=inv_es_id)
        inv = r["_source"]
    except Exception:
        return jsonify({"error": "not found"}), 404
    ip    = inv.get("ip", "")
    score = float(inv.get("ensemble_score", 0))
    sev   = inv.get("severity", "medium")
    es.update(index="soc-investigations", id=inv_es_id,
              body={"doc": {"status": "analyzing", "updated_at": datetime.utcnow().isoformat() + "Z"}})
    def _run():
        try:
            from llm_analyzer import analyze_incident
            analysis = analyze_incident(es, {"src_ip": ip, "anomaly_score": score, "severity": sev,
                                             "log_type": "ensemble", "timestamp": datetime.utcnow().isoformat()})
            if analysis:
                es.update(index="soc-investigations", id=inv_es_id, body={"doc": {
                    "llm_verdict":    analysis.get("verdict"),
                    "llm_summary":    analysis.get("summary"),
                    "llm_confidence": analysis.get("confidence"),
                    "llm_attack_type": analysis.get("attack_type"),
                    "llm_actions":    analysis.get("recommended_actions", []),
                    "llm_model":      analysis.get("model"),
                    "status":         "analyzed",
                    "updated_at":     datetime.utcnow().isoformat() + "Z",
                }})
        except Exception as e:
            es.update(index="soc-investigations", id=inv_es_id,
                      body={"doc": {"status": "new", "updated_at": datetime.utcnow().isoformat() + "Z"}})
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "analyzing"})

@app.route("/api/investigation/<inv_es_id>/promote", methods=["POST"])
@require_level("L2")
def api_investigation_promote(inv_es_id):
    """Promeut une investigation en incident formel."""
    try:
        r = es.get(index="soc-investigations", id=inv_es_id)
        inv = r["_source"]
    except Exception:
        return jsonify({"error": "not found"}), 404
    ip    = inv.get("ip", "")
    score = float(inv.get("ensemble_score", 0))
    sev   = inv.get("severity", "medium")
    level_map = {"critical": "L1", "high": "L1", "medium": "L2", "low": "L2"}
    title = f"[Ensemble] Détection multi-modèles — {ip} (score {round(score*100)}%)"
    votes = inv.get("votes", {})
    desc  = (f"Investigation #{inv.get('inv_id','?')} promue en incident.\n"
             f"IP: {ip} | Score ensemble: {round(score*100)}% | Sévérité: {sev}\n"
             f"Votes: IF={votes.get('if',0):.2f} RF={votes.get('rf',0):.2f} "
             f"DL={votes.get('dl',0):.2f} Rate={votes.get('rate',0):.2f}")
    try:
        inc = _make_incident(title, round(score * 10, 2), sev,
                             level_map.get(sev, "L2"), "ensemble_detection",
                             ip, desc, "ensemble",
                             {"ensemble_score": score, "model_votes": votes})
        es.update(index="soc-investigations", id=inv_es_id, body={"doc": {
            "status":     "promoted",
            "incident_id": inc["incident_id"],
            "updated_at":  datetime.utcnow().isoformat() + "Z",
        }})
        return jsonify({"status": "promoted", "incident_id": inc["incident_id"]}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/investigation/<inv_es_id>/logs")
@require_level("L1")
def api_investigation_logs(inv_es_id):
    """Retourne les derniers logs pour l'IP de cette investigation."""
    try:
        r = es.get(index="soc-investigations", id=inv_es_id)
        ip = r["_source"].get("ip", "")
    except Exception:
        return jsonify({"logs": []}), 404
    if not ip:
        return jsonify({"logs": []})
    try:
        rl = es.search(index="soc-logs*", size=20,
                       query={"bool": {"must": [
                           {"term": {"src_ip": ip}},
                           {"range": {"@timestamp": {"gte": "now-48h"}}}
                       ]}},
                       sort=[{"@timestamp": {"order": "desc"}}])
        logs = [h["_source"] for h in rl["hits"]["hits"]]
        return jsonify({"logs": logs, "ip": ip})
    except Exception as e:
        return jsonify({"logs": [], "error": str(e)})


# ─── MITRE ATT&CK mapping ────────────────────────────────────────────────────

MITRE_TECHNIQUES = [
    {
        "id": "T1190", "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "color": "red",
        "keywords": ["remote code execution", "rce", "sql injection", "sqli",
                     "ssrf", "server-side request", "path traversal", "directory traversal",
                     "file inclusion", "lfi", "rfi", "command injection", "deserialization",
                     "improper input validation", "unsafe deserialization", "xxe"],
    },
    {
        "id": "T1059", "name": "Command and Scripting Interpreter",
        "tactic": "Execution", "tactic_id": "TA0002",
        "color": "orange",
        "keywords": ["command execution", "code execution", "execute code",
                     "arbitrary command", "shell injection", "os command"],
    },
    {
        "id": "T1203", "name": "Exploitation for Client Execution",
        "tactic": "Execution", "tactic_id": "TA0002",
        "color": "orange",
        "keywords": ["use-after-free", "uaf", "buffer overflow", "heap overflow",
                     "stack overflow", "memory corruption", "out-of-bounds", "dangling pointer",
                     "type confusion"],
    },
    {
        "id": "T1068", "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "color": "purple",
        "keywords": ["privilege escalation", "escalate privilege", "local privilege",
                     "root privilege", "elevat", "gain root", "kernel exploit"],
    },
    {
        "id": "T1078", "name": "Valid Accounts",
        "tactic": "Defense Evasion / Initial Access", "tactic_id": "TA0001",
        "color": "yellow",
        "keywords": ["authentication bypass", "bypass authentication",
                     "improper access control", "access control bypass",
                     "unauthorized access", "unauthenticated"],
    },
    {
        "id": "T1552", "name": "Unsecured Credentials / Data Exposure",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "color": "yellow",
        "keywords": ["information disclosure", "sensitive data", "credential leak",
                     "password exposure", "secret", "token leak", "data exposure"],
    },
    {
        "id": "T1498", "name": "Network Denial of Service",
        "tactic": "Impact", "tactic_id": "TA0040",
        "color": "muted",
        "keywords": ["denial of service", "dos", "resource exhaustion",
                     "crash", "infinite loop", "memory exhaustion"],
    },
    {
        "id": "T1557", "name": "Man-in-the-Middle",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "color": "purple",
        "keywords": ["man-in-the-middle", "mitm", "ssl stripping", "tls bypass",
                     "certificate validation"],
    },
]

# Services running in the lab — maps keyword → exposure info
LAB_SERVICES = {
    "openssh":      {"name": "OpenSSH",       "host": "192.168.122.210:22",  "role": "VM Victime", "icon": "fa-terminal",    "color": "red"},
    "ssh":          {"name": "SSH",            "host": "192.168.122.210:22",  "role": "VM Victime", "icon": "fa-terminal",    "color": "red"},
    "apache":       {"name": "Apache HTTPD",   "host": "192.168.122.210:80",  "role": "VM Victime", "icon": "fa-server",      "color": "orange"},
    "httpd":        {"name": "Apache HTTPD",   "host": "192.168.122.210:80",  "role": "VM Victime", "icon": "fa-server",      "color": "orange"},
    "elasticsearch":{"name": "Elasticsearch",  "host": "192.168.50.10:9200","role": "SOC Plateforme","icon": "fa-database", "color": "yellow"},
    "flask":        {"name": "Flask SOC",      "host": "192.168.50.10:5000","role": "SOC Plateforme","icon": "fa-shield-alt","color": "blue"},
    "python":       {"name": "Python/Flask",   "host": "192.168.50.10:5000","role": "SOC Plateforme","icon": "fa-shield-alt","color": "blue"},
    "linux kernel": {"name": "Linux Kernel",   "host": "Toutes VMs",          "role": "Infrastructure", "icon": "fa-linux",   "color": "muted"},
    "linux":        {"name": "Linux",          "host": "Toutes VMs",          "role": "Infrastructure", "icon": "fa-linux",   "color": "muted"},
    "php":          {"name": "PHP",            "host": "192.168.122.210",     "role": "VM Victime", "icon": "fa-code",        "color": "purple"},
    "nginx":        {"name": "Nginx",          "host": "192.168.122.210:80",  "role": "VM Victime", "icon": "fa-server",      "color": "green"},
    "suricata":     {"name": "Suricata IDS",   "host": "192.168.50.10",     "role": "SOC Plateforme","icon": "fa-eye",      "color": "blue"},
    "logstash":     {"name": "Logstash",       "host": "192.168.50.10:5044","role": "SOC Plateforme","icon": "fa-filter",   "color": "green"},
    "kibana":       {"name": "Kibana",         "host": "192.168.50.10:5601","role": "SOC Plateforme","icon": "fa-chart-bar","color": "blue"},
}


def _enrich_cve(cve):
    """Enrichit un CVE avec MITRE ATT&CK et exposition lab."""
    desc = (cve.get("description", "") + " " + cve.get("cve_id", "")).lower()
    cvss = float(cve.get("cvss_score", 0))

    # MITRE techniques matching
    matched_techniques = []
    for tech in MITRE_TECHNIQUES:
        if any(kw in desc for kw in tech["keywords"]):
            matched_techniques.append(tech)

    # Lab exposure matching
    lab_hits = []
    seen_svc = set()
    for kw, svc in LAB_SERVICES.items():
        if kw in desc and svc["name"] not in seen_svc:
            lab_hits.append(svc)
            seen_svc.add(svc["name"])

    # Exploitation risk
    exploit_risk = "unknown"
    if "actively exploited" in desc or "exploit" in desc:
        exploit_risk = "high"
    elif lab_hits:
        exploit_risk = "medium" if cvss >= 9.5 else "low"

    # Related incidents (IPs that attacked our services)
    related_incidents = []
    if lab_hits:
        try:
            r = es.search(
                index="soc-incidents",
                size=3,
                query={"bool": {"must": [{"exists": {"field": "src_ip"}}],
                                "should": [{"term": {"severity.keyword": "critical"}},
                                           {"term": {"verdict": "true_positive"}}],
                                "minimum_should_match": 1}},
                _source=["incident_id", "src_ip", "title", "severity", "verdict", "created_at"],
            )
            related_incidents = [h["_source"] for h in r["hits"]["hits"]]
        except Exception:
            pass

    cve["_mitre"]     = matched_techniques
    cve["_lab_hits"]  = lab_hits
    cve["_exploit_risk"] = exploit_risk
    cve["_related_incidents"] = related_incidents
    return cve


@app.route("/cve")
@require_auth
def cve_page():
    raw_cves = es_search_with_id("soc-cve-alerts", size=50)
    total    = es_count("soc-cve-alerts")

    # Enrich each CVE
    cves = [_enrich_cve(c) for c in raw_cves]

    # Sort: lab-exposed + high CVSS first
    cves.sort(key=lambda c: (
        len(c["_lab_hits"]) > 0,
        float(c.get("cvss_score", 0)),
    ), reverse=True)

    # Stats
    lab_exposed  = sum(1 for c in cves if c["_lab_hits"])
    mitre_mapped = sum(1 for c in cves if c["_mitre"])
    critical_9   = sum(1 for c in cves if float(c.get("cvss_score", 0)) >= 9.5)

    return render_template("cve.html",
        cves=cves,
        total=total,
        lab_exposed=lab_exposed,
        mitre_mapped=mitre_mapped,
        critical_9=critical_9,
        current_user=get_current_user(),
    )


@app.route("/api/cve/<cve_doc_id>/status", methods=["POST"])
@require_level("L2")
def api_cve_status(cve_doc_id):
    """Marquer une CVE comme résolue ou réouverte."""
    data   = request.get_json(force=True) or {}
    status = data.get("status", "resolved")
    if status not in ("resolved", "open"):
        return jsonify({"error": "statut invalide"}), 400
    try:
        update_doc = {"status": status}
        if status == "resolved":
            update_doc["resolved_at"] = datetime.now(timezone.utc).isoformat()
            update_doc["resolved_by"] = session.get("username", "unknown")
        else:
            update_doc["resolved_at"] = None
        es.update(index="soc-cve-alerts", id=cve_doc_id, doc=update_doc)
        audit_log(f"cve_{status}", username=session.get("username"), details={"cve_id": cve_doc_id})
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/tailscale")
@require_level("L2")
def tailscale_page():
    machines  = get_tailscale_status()
    vm_config = load_vm_config()
    # Enrichir chaque machine avec son rôle configuré
    ip_to_role = {v["ip"]: {"key": k, **v} for k, v in vm_config.items()}
    for m in machines:
        cfg = ip_to_role.get(m["ip"], {})
        m["role"]     = cfg.get("role", "Autre")
        m["vm_key"]   = cfg.get("key", "")
        m["vm_tools"] = cfg.get("tools", "")
    return render_template("tailscale.html", machines=machines, vm_config=vm_config, vm_roles=list(VM_ROLES.keys()))

@app.route("/api/vm_config", methods=["GET"])
def api_vm_config_get():
    return jsonify(load_vm_config())

@app.route("/api/vm_config", methods=["POST"])
def api_vm_config_post():
    data = request.json or {}
    cfg  = load_vm_config()
    # data: {"vm_soc": {"ip": "...", "hostname": "..."}, ...}
    # ou assignment direct: {"ip": "...", "role": "...", "hostname": "..."}
    for key, vals in data.items():
        if key not in cfg:
            cfg[key] = {"role": "Autre", "ip": "", "hostname": "", "tools": ""}
        cfg[key].update(vals)
        # Mettre à jour les tools selon le rôle
        role = cfg[key].get("role", "Autre")
        if role in VM_ROLES:
            cfg[key]["tools"] = VM_ROLES[role]["tools"]
    save_vm_config(cfg)
    return jsonify({"status": "saved", "config": cfg})


@app.route("/incidents")
@require_auth
def incidents_page():
    user    = get_current_user()
    page    = max(1, int(request.args.get("page", 1)))
    size    = min(100, max(10, int(request.args.get("size", 50))))
    f_sev   = request.args.get("severity", "")
    f_stat  = request.args.get("status", "")
    f_verd  = request.args.get("verdict", "")
    f_q     = request.args.get("q", "").strip()

    must_clauses = []
    if f_sev:  must_clauses.append({"term": {"severity": f_sev}})
    if f_stat: must_clauses.append({"term": {"status":   f_stat}})
    if f_verd: must_clauses.append({"term": {"verdict":  f_verd}})
    if user and LEVEL_ORDER.get(user["level"], 0) < LEVEL_ORDER["L2"]:
        must_clauses.append({"bool": {"should": [
            {"term": {"assigned_to": user["name"]}},
            {"term": {"assigned_to": ""}},
            {"term": {"assigned_to": "None"}},
        ], "minimum_should_match": 1}})

    if f_q:
        query = {"bool": {"must": must_clauses + [
            {"multi_match": {"query": f_q, "fields": ["title", "src_ip", "description", "incident_id"]}}
        ]}} if must_clauses else {"multi_match": {"query": f_q, "fields": ["title", "src_ip", "description", "incident_id"]}}
    else:
        query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}

    try:
        r = es.search(index="soc-incidents", query=query, size=size,
                      from_=(page - 1) * size,
                      sort=[{"created_at": {"order": "desc"}}])
        incidents = [{"id": h["_id"], **h["_source"]} for h in r["hits"]["hits"]]
        total     = r["hits"]["total"]["value"]
    except Exception:
        incidents, total = [], 0

    total_pages = max(1, -(-total // size))  # ceiling division
    my_alert = next((i for i in incidents if i.get("assigned_to","") == (user["name"] if user else "SOC")
                     and i.get("status") != "closed"), None)
    return render_template("incidents.html", incidents=incidents, total=total,
                           my_alert=my_alert, current_user=user,
                           page=page, size=size, total_pages=total_pages,
                           f_sev=f_sev, f_stat=f_stat, f_verd=f_verd, f_q=f_q)

@app.route("/incidents/new", methods=["POST"])
@require_level("L2")
def create_incident():
    title    = request.form.get("title", "").strip()
    severity = request.form.get("severity", "medium")
    itype    = request.form.get("itype", "autre")
    assigned = request.form.get("assigned", "").strip()
    level    = request.form.get("level", "L1")
    desc     = request.form.get("description", "").strip()
    src_ip   = request.form.get("src_ip", "").strip()
    if not title:
        return redirect(url_for("incidents_page"))
    # Auto-assign si non spécifié
    if not assigned or assigned == "None":
        assigned, level = auto_assign(severity)
        assigned = assigned or "None"
    _created_at = datetime.utcnow().isoformat() + "Z"
    doc = {
        "incident_id": str(uuid.uuid4())[:8].upper(),
        "title": title,
        "severity": severity,
        "type": itype,
        "status": "awaiting_action",
        "verdict": "none",
        "assigned_to": assigned or "None",
        "level": level,
        "description": desc,
        "src_ip": src_ip,
        "created_at": _created_at,
        "updated_at": _created_at,
        "notes": [],
        "sla_deadline": _sla_deadline(severity, _created_at),
        "sla_status":   "ok",
    }
    try:
        result = es.index(index="soc-incidents", document=doc)
        doc_id = result["_id"]
        doc["incident_id"] = doc.get("incident_id", doc_id)
        notifier.notify("new_incident", doc)
        if assigned and assigned not in ("None", ""):
            push_notif(assigned,
                f"📋 Incident {doc['incident_id']} assigné : {title}",
                notif_type="warning", incident_id=doc_id, severity=severity)
        # AbuseIPDB async
        if _ABUSEIPDB_KEY and src_ip:
            def _enrich_manual(did, ip):
                rep = get_ip_reputation(ip)
                if rep:
                    try: es.update(index="soc-incidents", id=did, body={"doc": {"ip_reputation": rep}})
                    except Exception: pass
            threading.Thread(target=_enrich_manual, args=(doc_id, src_ip), daemon=True).start()
        # SOAR auto-analysis for critical/high incidents
        if severity in ("critical", "high"):
            soar_auto_analyze(doc_id, doc)
    except:
        pass
    return redirect(url_for("incidents_page"))

@app.route("/incidents/<inc_id>/update", methods=["POST"])
def update_incident(inc_id):
    try:
        doc = es.get(index="soc-incidents", id=inc_id)
        src = doc["_source"]
        for field in ["status", "verdict", "assigned_to", "level", "severity"]:
            val = request.form.get(field)
            if val is not None:
                src[field] = val
        note_text = request.form.get("note", "").strip()
        if note_text:
            user = get_current_user()
            src.setdefault("notes", []).append({
                "text": note_text,
                "author": user["name"] if user else src.get("assigned_to", "SOC"),
                "at": datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            })
            audit_log("incident_note", details={"incident_id": inc_id, "note_preview": note_text[:60]})
        lessons = request.form.get("lessons_learned", "").strip()
        if lessons:
            src["lessons_learned"] = lessons
        src["updated_at"] = datetime.utcnow().isoformat() + "Z"
        audit_log("incident_update", details={"incident_id": inc_id,
                  "fields": [f for f in ["status","verdict","severity"] if request.form.get(f)]})
        es.index(index="soc-incidents", id=inc_id, document=src)

        # Notify on assignment change
        new_assignee = request.form.get("assigned_to")
        old_assignee = doc["_source"].get("assigned_to", "")
        if new_assignee and new_assignee != old_assignee and new_assignee not in ("", "None"):
            notifier.notify("assigned", src,
                extra=f"Assigné de « {old_assignee or 'Non assigné'} » → « {new_assignee} »")
            iid2 = src.get("incident_id", inc_id)
            sev2 = src.get("severity", "medium")
            push_notif(new_assignee,
                f"📋 Incident {iid2} vous a été assigné ({sev2.upper()})",
                notif_type="warning" if sev2 in ("critical","high") else "info",
                incident_id=inc_id, severity=sev2)

        # Notify on level escalation
        new_level = request.form.get("level")
        old_level  = doc["_source"].get("level", "")
        level_order = {"L1": 1, "L2": 2, "L3": 3}
        if new_level and level_order.get(new_level, 0) > level_order.get(old_level, 0):
            notifier.notify("escalated", src,
                extra=f"Escalade {old_level} → {new_level}")
            iid3 = src.get("incident_id", inc_id)
            sev3 = src.get("severity", "medium")
            # Notifier tous les L3 d'une escalade
            users_esc = _load_users()
            for uname, udata in users_esc.items():
                if udata.get("level") == "L3":
                    push_notif(uname,
                        f"⬆️ Escalade {old_level}→{new_level} : {iid3} ({sev3.upper()})",
                        notif_type="warning", incident_id=inc_id, severity=sev3)
    except:
        pass
    # Redirect back to detail page if that's where the form was submitted from
    referrer = request.referrer or ""
    if f"/incidents/{inc_id}" in referrer:
        return redirect(url_for("incident_detail", inc_id=inc_id))
    return redirect(url_for("incidents_page"))


@app.route("/incidents/<inc_id>/close", methods=["POST"])
@require_level("L2")
def close_incident(inc_id):
    """Clôture un incident avec verdict, résolution et lessons learned."""
    data       = request.get_json(force=True) or {}
    verdict    = data.get("verdict", "true_positive")
    resolution = data.get("resolution", "").strip()
    lessons    = data.get("lessons_learned", "").strip()
    if not resolution:
        return jsonify({"error": "La résolution est obligatoire."}), 400
    try:
        now  = datetime.now(timezone.utc).isoformat()
        user = get_current_user()
        doc  = es.get(index="soc-incidents", id=inc_id)
        src  = doc["_source"]
        src.update({
            "status": "closed",
            "verdict": verdict,
            "resolution": resolution,
            "lessons_learned": lessons,
            "closed_at": now,
            "closed_by": session.get("username", "unknown"),
            "updated_at": now,
            "post_incident_report": (
                f"Rapport de clôture {now[:10]} — par {session.get('username','?')}\n"
                f"Verdict: {verdict}\nRésolution: {resolution}\n"
                f"Lessons learned: {lessons or 'N/A'}"
            ),
        })
        es.index(index="soc-incidents", id=inc_id, document=src)
        audit_log("incident_closed", username=session.get("username"), details={
            "incident_id": src.get("incident_id", inc_id),
            "verdict": verdict,
            "severity": src.get("severity", "?")
        })
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents/bulk_action", methods=["POST"])
@require_level("L2")
def api_incidents_bulk_action():
    """Actions groupées sur plusieurs incidents (L1+)."""
    data   = request.get_json(force=True) or {}
    ids    = data.get("ids", [])
    action = data.get("action", "")
    if not ids or not action:
        return jsonify({"error": "ids et action sont requis"}), 400
    if len(ids) > 100:
        return jsonify({"error": "Maximum 100 incidents par action groupée"}), 400

    allowed_actions = {"close", "in_progress", "awaiting_action", "assign"}
    if action not in allowed_actions:
        return jsonify({"error": f"Action inconnue: {action}"}), 400

    user     = get_current_user() or {}
    username = session.get("username", "unknown")
    now      = datetime.now(timezone.utc).isoformat()
    results  = {"ok": [], "error": []}

    for inc_id in ids:
        try:
            doc = es.get(index="soc-incidents", id=inc_id)
            src = doc["_source"]
            if action in ("in_progress", "awaiting_action"):
                src["status"]     = action
                src["updated_at"] = now
            elif action == "close":
                src["status"]     = "closed"
                src["closed_at"]  = now
                src["closed_by"]  = username
                src["updated_at"] = now
                if not src.get("resolution"):
                    src["resolution"] = f"Clôture groupée par {username}"
            elif action == "assign":
                assignee = data.get("assignee", "")
                level    = data.get("level", "L1")
                if not assignee:
                    results["error"].append(inc_id)
                    continue
                src["assigned_to"] = assignee
                src["level"]       = level
                src["updated_at"]  = now
            es.index(index="soc-incidents", id=inc_id, document=src)
            results["ok"].append(inc_id)
        except Exception:
            results["error"].append(inc_id)

    audit_log("incident_bulk_action", username=username, details={
        "action": action, "count": len(results["ok"]), "ids": results["ok"]
    })
    return jsonify({"status": "ok", "updated": len(results["ok"]), "errors": len(results["error"])})


# ─── API ────────────────────────────────────────────────────────────────────

@app.route("/api/incident_config", methods=["GET", "POST"])
def incident_config_api():
    cfg = load_incident_config()
    if request.method == "POST":
        data = request.json or {}
        if "enabled"   in data: cfg["enabled"]   = bool(data["enabled"])
        if "min_score" in data: cfg["min_score"] = float(data["min_score"])
        if "max_score" in data: cfg["max_score"] = float(data["max_score"])
        save_incident_config(cfg)
    return jsonify(cfg)

_geoip_cache = {}

# ═══════════════════════════════════════════════════════════════
#  SLA — deadlines par sévérité (heures)
# ═══════════════════════════════════════════════════════════════
_SLA_HOURS = {"critical": 4, "high": 8, "medium": 24, "low": 72}

def _sla_deadline(severity: str, created_at: str) -> str:
    """Retourne l'ISO deadline SLA à partir de la sévérité et de created_at."""
    hours = _SLA_HOURS.get(severity, 24)
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except Exception:
        dt = datetime.now(timezone.utc)
    return (dt + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

def _sla_status(severity: str, created_at: str, closed_at: str = None) -> str:
    """Retourne 'ok', 'at_risk' (>75% écoulé), ou 'breached'."""
    hours = _SLA_HOURS.get(severity, 24)
    try:
        dt_created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        dt_ref     = datetime.fromisoformat(closed_at.replace("Z", "+00:00")) if closed_at else datetime.now(timezone.utc)
        elapsed_h  = (dt_ref - dt_created).total_seconds() / 3600
        ratio      = elapsed_h / hours
        if ratio >= 1.0:  return "breached"
        if ratio >= 0.75: return "at_risk"
        return "ok"
    except Exception:
        return "ok"


# ═══════════════════════════════════════════════════════════════
#  AbuseIPDB — cache + enrichissement
# ═══════════════════════════════════════════════════════════════
_abuseipdb_cache: dict = {}  # ip → {score, isp, country, categories, cached_at}
_ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

def get_ip_reputation(ip: str) -> dict | None:
    """
    Interroge AbuseIPDB v2. Résultat mis en cache 24h.
    Retourne None si clé absente ou IP privée.
    """
    if not _ABUSEIPDB_KEY:
        return None
    if not ip or ip.startswith(("192.168.", "10.", "172.16.", "172.17.",
                                "172.18.", "172.19.", "172.20.", "172.21.",
                                "172.22.", "172.23.", "172.24.", "172.25.",
                                "172.26.", "172.27.", "172.28.", "172.29.",
                                "172.30.", "172.31.", "127.", "100.", "::1")):
        return None
    # Vérifier cache (24h)
    cached = _abuseipdb_cache.get(ip)
    if cached:
        try:
            age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(cached["cached_at"])).total_seconds() / 3600
            if age_h < 24:
                return cached
        except Exception:
            pass
    try:
        r = _requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            timeout=5
        )
        if r.status_code != 200:
            return None
        d = r.json().get("data", {})
        result = {
            "abuse_score":    d.get("abuseConfidenceScore", 0),
            "total_reports":  d.get("totalReports", 0),
            "country":        d.get("countryCode", ""),
            "isp":            d.get("isp", ""),
            "domain":         d.get("domain", ""),
            "is_tor":         d.get("isTor", False),
            "is_public":      d.get("isPublic", True),
            "last_reported":  (d.get("lastReportedAt") or "")[:10],
            "cached_at":      datetime.now(timezone.utc).isoformat(),
        }
        _abuseipdb_cache[ip] = result
        return result
    except Exception:
        return None


def get_geoip(ip):
    if not ip or ip.startswith(("192.168.", "10.", "172.", "127.", "100.")):
        return None
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    try:
        r = _requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,org", timeout=3)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") != "fail":
                result = {
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                }
                _geoip_cache[ip] = result
                return result
    except Exception:
        pass
    return None

def _make_incident(title, score, severity, level, itype, src_ip, description, source, extra=None):
    # Auto-assigner selon la sévérité
    assigned_name, assigned_level = auto_assign(severity)
    created_at = datetime.utcnow().isoformat() + "Z"
    doc = {
        "incident_id": str(uuid.uuid4())[:8].upper(),
        "title": title, "severity": severity, "type": itype,
        "status": "awaiting_action", "verdict": "none",
        "assigned_to": assigned_name or "None", "level": assigned_level or level,
        "description": description, "src_ip": src_ip,
        "created_at": created_at,
        "updated_at": created_at,
        "notes": [], "auto_generated": True,
        "source": source, "unified_score": round(score, 4),
        "ai_analysis": None,
        # ── SLA ──────────────────────────────────────────────
        "sla_deadline": _sla_deadline(severity, created_at),
        "sla_status":   "ok",
        **(extra or {})
    }
    # GeoIP enrichment (non-blocking, skip private IPs)
    geo = get_geoip(src_ip)
    if geo:
        doc["geoip"] = geo
    # AbuseIPDB enrichment (async pour ne pas bloquer la création)
    if _ABUSEIPDB_KEY and src_ip:
        def _enrich_reputation(doc_id_inner, ip):
            rep = get_ip_reputation(ip)
            if rep:
                try:
                    es.update(index="soc-incidents", id=doc_id_inner,
                              body={"doc": {"ip_reputation": rep}})
                except Exception:
                    pass
        # sera lancé après l'indexation (doc_id connu plus bas)
        doc["_enrich_ip"] = src_ip

    enrich_ip = doc.pop("_enrich_ip", None)
    result = es.index(index="soc-incidents", document=doc)
    doc_id = result["_id"]

    # AbuseIPDB enrichment asynchrone
    if enrich_ip:
        def _enrich(did, ip):
            rep = get_ip_reputation(ip)
            if rep:
                try:
                    es.update(index="soc-incidents", id=did, body={"doc": {"ip_reputation": rep}})
                except Exception:
                    pass
        threading.Thread(target=_enrich, args=(doc_id, enrich_ip), daemon=True).start()

    # Notify stakeholders via configured channels (email + webhook)
    notifier.notify("new_incident", {**doc, "anomaly_score": score})

    # In-app notification → assigné + tous les L2/L3
    iid = doc["incident_id"]
    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
    if assigned_name and assigned_name not in ("None", ""):
        push_notif(assigned_name,
            f"{sev_emoji} Incident {iid} assigné : {title}",
            notif_type="critical" if severity == "critical" else "warning",
            incident_id=doc_id, severity=severity)
    # Notifier les L2/L3 pour les incidents critical
    if severity == "critical":
        users_all = _load_users()
        for uname, udata in users_all.items():
            if udata.get("level") in ("L2", "L3") and uname != assigned_name:
                push_notif(uname,
                    f"🔴 CRITIQUE — {iid} : {title} depuis {src_ip}",
                    notif_type="critical", incident_id=doc_id, severity=severity)

    # Analyse LLM en arrière-plan — ne bloque pas la réponse Flask
    def _run_llm():
        try:
            analysis = analyze_incident(es, {
                "src_ip":        src_ip,
                "log_type":      itype,
                "anomaly_score": score,
                "severity":      severity,
                "timestamp":     doc["created_at"],
            })
            if analysis:
                # Sauvegarder à plat (pour stats/requêtes) + objet complet
                es.update(index="soc-incidents", id=doc_id, body={"doc": {
                    "ai_analysis":       analysis,
                    "llm_verdict":       analysis.get("verdict"),
                    "llm_attack_type":   analysis.get("attack_type"),
                    "llm_confidence":    analysis.get("confidence"),
                    "llm_summary":       analysis.get("summary"),
                    "llm_actions":       analysis.get("actions") or analysis.get("recommended_actions") or [],
                    "llm_model":         analysis.get("model"),
                    "llm_analyzed_at":   analysis.get("analyzed_at"),
                }})
        except Exception as e:
            import logging
            logging.getLogger("llm").error(f"LLM update error: {e}")

    threading.Thread(target=_run_llm, daemon=True).start()
    # SOAR: auto-analysis for critical/high
    if severity in ("critical", "high"):
        soar_auto_analyze(doc_id, doc)
    return doc

def _severity_from_score(score):
    # score sur échelle 0–10
    if score >= 9.0: return "critical", "L3"
    if score >= 7.0: return "high",     "L2"
    if score >= 4.0: return "medium",   "L1"
    return "low", "L1"

@app.route("/api/auto_incident", methods=["POST"])
def auto_incident():
    global auto_incident_seen
    incident_config = load_incident_config()
    if not incident_config.get("enabled"):
        return jsonify({"status": "disabled"}), 200
    data     = request.json or {}
    raw_score = float(data.get("anomaly_score", 0))
    score    = round(raw_score * 10, 4)   # IA 0–1 → échelle 0–10
    log_ts   = data.get("timestamp", "")
    src_ip   = data.get("src_ip", "")
    log_type = data.get("log_type", "")
    ssh_user = data.get("ssh_user", "")
    if not (incident_config["min_score"] <= score <= incident_config["max_score"]):
        return jsonify({"status": "out_of_range"}), 200
    dedup_key = f"ia_{src_ip}_{log_ts[:16]}_{round(score,1)}"
    if dedup_key in auto_incident_seen:
        return jsonify({"status": "duplicate"}), 200
    auto_incident_seen.add(dedup_key)
    if len(auto_incident_seen) > 1000:
        auto_incident_seen = set(list(auto_incident_seen)[-500:])
    severity, level = _severity_from_score(score)
    type_map = {"auth": "brute_force", "apache_access": "web_attack", "syslog": "ids_alert"}
    itype = type_map.get(log_type, "anomaly_ia")
    title = f"[IA] {log_type} — score {score:.1f}/10" + (f" — {src_ip}" if src_ip else "")
    try:
        _make_incident(title, score, severity, level, itype, src_ip,
            f"Isolation Forest — Score: {score:.1f}/10 (brut: {raw_score:.4f}) | IP: {src_ip} | SSH user: {ssh_user}",
            "ia", {"anomaly_score": raw_score})
        return jsonify({"status": "created", "title": title}), 201
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route("/api/auto_incident_ensemble", methods=["POST"])
def auto_incident_ensemble():
    """Endpoint dédié à l'ensemble detector — score 0-1, seuil propre."""
    global auto_incident_seen
    data          = request.json or {}
    ensemble_score = float(data.get("anomaly_score", 0))
    src_ip        = data.get("src_ip", "")
    log_type      = data.get("log_type", "auth")
    ssh_user      = data.get("ssh_user", "")
    severity      = data.get("severity", "medium")
    votes         = int(data.get("votes", 2))
    if_s  = float(data.get("if_score", 0))
    rf_s  = float(data.get("rf_score", 0))
    dl_s  = float(data.get("dl_score", 0))
    rate  = int(data.get("rate_count", 0))
    if ensemble_score < 0.28:
        return jsonify({"status": "below_threshold"}), 200
    dedup_key = f"ens_{src_ip}_{datetime.utcnow().strftime('%Y-%m-%dT%H')}"
    if dedup_key in auto_incident_seen:
        return jsonify({"status": "duplicate"}), 200
    auto_incident_seen.add(dedup_key)
    if len(auto_incident_seen) > 1000:
        auto_incident_seen = set(list(auto_incident_seen)[-500:])
    score10 = round(ensemble_score * 10, 2)
    type_map = {"auth": "brute_force", "apache_access": "web_attack", "syslog": "ids_alert"}
    itype = type_map.get(log_type, "anomaly_ia")
    title = f"[Ensemble] {severity.upper()} — {src_ip} (score {score10:.1f}/10, {votes}/4 votes)"
    desc = (f"Ensemble (IF×0.30+RF×0.35+DL×0.20+Rate×0.15) — Score: {score10:.1f}/10 | "
            f"Votes: {votes}/4 | IF={if_s:.3f} RF={rf_s:.3f} DL={dl_s:.3f} Rate={rate} | "
            f"IP: {src_ip} | User: {ssh_user}")
    try:
        _make_incident(title, score10, severity, None, itype, src_ip, desc,
                       "ensemble", {"anomaly_score": ensemble_score, "votes": votes,
                                    "if_score": if_s, "rf_score": rf_s, "dl_score": dl_s})
        return jsonify({"status": "created", "title": title}), 201
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500


@app.route("/api/auto_incident_cve", methods=["POST"])
def auto_incident_cve():
    global auto_incident_seen
    incident_config = load_incident_config()
    if not incident_config.get("enabled"):
        return jsonify({"status": "disabled"}), 200
    data   = request.json or {}
    cvss   = float(data.get("cvss_score", 0))
    cve_id = data.get("cve_id", "")
    desc   = data.get("description", "")
    score  = cvss   # CVSS déjà en 0–10
    if not (incident_config["min_score"] <= score <= incident_config["max_score"]):
        return jsonify({"status": "out_of_range"}), 200
    dedup_key = f"cve_{cve_id}"
    if dedup_key in auto_incident_seen:
        return jsonify({"status": "duplicate"}), 200
    # Persistent dedup: check ES so restarts don't recreate existing incidents
    try:
        existing = es.count(index="soc-incidents",
                            query={"term": {"cve_id.keyword": cve_id}})
        if existing["count"] > 0:
            auto_incident_seen.add(dedup_key)
            return jsonify({"status": "duplicate"}), 200
    except Exception:
        pass
    auto_incident_seen.add(dedup_key)
    severity, level = _severity_from_score(score)
    title = f"[CVE] {cve_id} — CVSS {cvss}/10"
    try:
        _make_incident(title, score, severity, level, "cve", "",
            f"CVE NVD API — CVSS: {cvss}/10\n{desc[:300]}",
            "cve", {"cvss_score": cvss, "cve_id": cve_id})
        return jsonify({"status": "created", "title": title}), 201
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route("/api/alert", methods=["POST"])
def receive_alert():
    data       = request.json or {}
    alert_type = data.get("alert_type", "unknown")
    enriched   = {
        "timestamp":   datetime.now().isoformat(),
        "alert_type":  alert_type,
        "severity":    data.get("severity", "medium"),
        "raw_data":    data,
        "explanation": ENRICHMENT.get(alert_type, {}).get("explanation", "Alerte non catégorisée"),
        "actions":     ENRICHMENT.get(alert_type, {}).get("actions", [])
    }
    try:
        es.index(index="soc-flask-alerts", document=enriched)
    except Exception as e:
        print(f"[alert] ES error: {e}")
    return jsonify({"status": "received"}), 201

@app.route("/api/alerts")
def get_alerts():
    return jsonify(es_search("soc-flask-alerts", size=50,
                             sort=[{"timestamp": {"order": "desc"}}]))

@app.route("/api/stats")
def get_stats():
    alerts_list = es_search("soc-flask-alerts", size=200)
    by_type, by_severity = {}, {}
    for a in alerts_list:
        by_type[a.get("alert_type", "?")] = by_type.get(a.get("alert_type", "?"), 0) + 1
        by_severity[a.get("severity", "?")] = by_severity.get(a.get("severity", "?"), 0) + 1
    return jsonify({"total": len(alerts_list), "by_type": by_type, "by_severity": by_severity})

def _pdf_safe(text):
    """Remplace les caractères hors latin-1 pour la police Helvetica de fpdf2."""
    s = str(text)
    replacements = {
        '—': '-', '–': '-', '’': "'", '‘': "'",
        '“': '"', '”': '"', '…': '...',
        'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
        'à': 'a', 'â': 'a', 'ä': 'a',
        'î': 'i', 'ï': 'i', 'ô': 'o', 'ö': 'o',
        'ù': 'u', 'û': 'u', 'ü': 'u', 'ç': 'c',
        'É': 'E', 'È': 'E', 'Ê': 'E', 'À': 'A',
        'Î': 'I', 'Ô': 'O', 'Ù': 'U', 'Ç': 'C',
    }
    for char, repl in replacements.items():
        s = s.replace(char, repl)
    return s.encode('latin-1', errors='replace').decode('latin-1')


@app.route("/report/pdf")
def generate_pdf():
    total_logs      = es_count("soc-logs*")
    total_anomalies = es_count("soc-anomalies")
    total_cve       = es_count("soc-cve-alerts")
    ssh_failed      = es_count("soc-logs*", {"term": {"tags": "ssh_failed"}})
    ia_critical     = es_count("soc-anomalies", {"range": {"anomaly_score": {"gte": 0.7}}})
    cve_critical    = es_count("soc-cve-alerts", {"range": {"cvss_score": {"gte": 7.0}}})
    risk_score      = compute_risk_score(ssh_failed, ia_critical, cve_critical)

    # Derniers incidents
    try:
        r = es.search(index="soc-incidents", query={"match_all": {}}, size=10,
                      sort=[{"created_at": {"order": "desc"}}])
        incidents = [h["_source"] for h in r["hits"]["hits"]]
    except:
        incidents = []

    # Top CVE
    try:
        r2 = es.search(index="soc-cve-alerts", query={"match_all": {}}, size=5,
                       sort=[{"cvss_score": {"order": "desc"}}])
        top_cves = [h["_source"] for h in r2["hits"]["hits"]]
    except:
        top_cves = []

    # Top anomalies IA
    try:
        r3 = es.search(index="soc-anomalies", query={"match_all": {}}, size=5,
                       sort=[{"anomaly_score": {"order": "desc"}}])
        top_anomalies = [h["_source"] for h in r3["hits"]["hits"]]
    except:
        top_anomalies = []

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    class SOCPdf(FPDF):
        def header(self):
            self.set_font("Helvetica", "B", 9)
            self.set_text_color(100, 100, 100)
            self.cell(0, 8, "Mini-SOC - Rapport de securite confidentiel", align="L")
            self.ln(2)
            self.set_draw_color(200, 200, 200)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Mini-SOC - PFA 2025-2026   |   Page {self.page_no()} / {{nb}}", align="C")

    pdf = SOCPdf()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # En-tête
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, "Mini-SOC - Rapport de securite", align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"Genere le : {now}", align="C")
    pdf.ln(10)

    # Score de risque
    risk_label = "CRITIQUE" if risk_score >= 7 else "ELEVE" if risk_score >= 4 else "MODERE" if risk_score >= 2 else "FAIBLE"
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, f"Score de risque global : {risk_score}/10  [{risk_label}]")
    pdf.ln(8)
    pdf.set_draw_color(180, 180, 180)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    # 1. Stats generales
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 7, "1. Statistiques generales (24h)")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 10)
    stats = [
        ("Logs indexes (total)",                 total_logs),
        ("Logs dernières 24h",                   es_count("soc-logs*", {"range": {"@timestamp": {"gte": "now-24h"}}})),
        ("SSH Failed",                           ssh_failed),
        ("Anomalies IA (Isolation Forest)",      total_anomalies),
        ("Anomalies DL (Autoencoder)",           es_count("soc-dl-anomalies")),
        ("Anomalies critiques (score >= 0.7)",   ia_critical),
        ("CVE totales",                          total_cve),
        ("CVE critiques (CVSS >= 7)",            cve_critical),
        ("Incidents total",                      es_count("soc-incidents")),
        ("Incidents ouverts",                    es_count("soc-incidents", {"term": {"status": "awaiting_action"}})),
    ]
    for label, val in stats:
        pdf.cell(0, 6, f"   {label} : {val}")
        pdf.ln(6)
    pdf.ln(4)

    # 2. Derniers incidents
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "2. Derniers incidents (10)")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 9)
    if incidents:
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(22, 6, "Score",    border=1, fill=True)
        pdf.cell(22, 6, "Severite", border=1, fill=True)
        pdf.cell(28, 6, "Statut",   border=1, fill=True)
        pdf.cell(22, 6, "Verdict",  border=1, fill=True)
        pdf.cell(96, 6, "Titre",    border=1, fill=True)
        pdf.ln()
        for inc in incidents:
            score   = str(inc.get("unified_score", ""))[:6]
            sev     = _pdf_safe(inc.get("severity", ""))[:10]
            status  = _pdf_safe(inc.get("status", ""))[:14]
            verdict = _pdf_safe(inc.get("verdict", "none"))[:10]
            title   = _pdf_safe(inc.get("title", ""))[:48]
            pdf.cell(22, 6, score,   border=1)
            pdf.cell(22, 6, sev,     border=1)
            pdf.cell(28, 6, status,  border=1)
            pdf.cell(22, 6, verdict, border=1)
            pdf.cell(96, 6, title,   border=1)
            pdf.ln()
    else:
        pdf.cell(0, 6, "   Aucun incident.")
        pdf.ln(6)
    pdf.ln(4)

    # 3. Top anomalies IA
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "3. Top 5 anomalies IA (Isolation Forest)")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 9)
    if top_anomalies:
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(38, 6, "Timestamp",  border=1, fill=True)
        pdf.cell(22, 6, "Score",      border=1, fill=True)
        pdf.cell(22, 6, "Severite",   border=1, fill=True)
        pdf.cell(38, 6, "IP source",  border=1, fill=True)
        pdf.cell(70, 6, "Type",       border=1, fill=True)
        pdf.ln()
        for a in top_anomalies:
            ts  = _pdf_safe(str(a.get("@timestamp", ""))[:16])
            sc  = str(round(a.get("anomaly_score", 0), 4))
            sev = _pdf_safe(a.get("severity", ""))[:10]
            ip  = _pdf_safe(a.get("src_ip", "") or "—")[:18]
            lt  = _pdf_safe(a.get("log_type", ""))[:28]
            pdf.cell(38, 6, ts,  border=1)
            pdf.cell(22, 6, sc,  border=1)
            pdf.cell(22, 6, sev, border=1)
            pdf.cell(38, 6, ip,  border=1)
            pdf.cell(70, 6, lt,  border=1)
            pdf.ln()
    else:
        pdf.cell(0, 6, "   Aucune anomalie.")
        pdf.ln(6)
    pdf.ln(4)

    # 4. Top CVE
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "4. Top CVE critiques")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 9)
    if top_cves:
        for cve in top_cves:
            cve_id  = _pdf_safe(cve.get('cve_id', ''))
            cvss    = str(cve.get('cvss_score', ''))
            desc    = _pdf_safe(cve.get('description', ''))[:90]
            pdf.multi_cell(190, 5, f"   {cve_id}  CVSS:{cvss}  {desc}")
    else:
        pdf.cell(0, 6, "   Aucune CVE.")
        pdf.ln(6)
    pdf.ln(4)

    # 5. Recommandations
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "5. Recommandations")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 10)
    if risk_score >= 7:
        reco_lines = [
            "NIVEAU : CRITIQUE",
            "- Bloquer immediatement les IPs suspectes (iptables / pare-feu)",
            "- Isoler les machines compromises du reseau",
            "- Contacter immediatement le responsable securite",
            "- Lancer une analyse forensique des logs et artefacts",
            "- Preparer un rapport d'incident complet",
        ]
    elif risk_score >= 4:
        reco_lines = [
            "NIVEAU : ELEVE",
            "- Renforcer la surveillance des anomalies critiques",
            "- Analyser les IPs les plus actives dans Kibana",
            "- Verifier et mettre a jour les regles pare-feu",
            "- Appliquer les patches CVE identifies en priorite",
        ]
    else:
        reco_lines = [
            "NIVEAU : FAIBLE",
            "- Maintenir la surveillance standard",
            "- Effectuer un audit securite hebdomadaire",
            "- Verifier la couverture des regles de detection",
        ]
    for line in reco_lines:
        pdf.cell(0, 6, f"   {line}")
        pdf.ln(6)

    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, "Mini-SOC - PFA 2025-2026", align="C")
    pdf.ln(5)

    filename = f"rapport-soc-{datetime.utcnow().strftime('%Y%m%d-%H%M')}.pdf"
    response = make_response(bytes(pdf.output()))
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


# ─── ANALYTICS PAGE ──────────────────────────────────────────────────────────

@app.route("/analytics")
@require_level("L2")
def analytics_page():
    return render_template("analytics.html")

# ─── APIs GRAPHIQUES (Chart.js) ───────────────────────────────────────────────

@app.route("/api/logs/timeline")
def api_logs_timeline():
    try:
        r = es.search(
            index="soc-logs*",
            size=0,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={"by_hour": {"date_histogram": {
                "field": "@timestamp", "calendar_interval": "1h"
            }}}
        )
        return jsonify([
            {"time": b["key_as_string"], "count": b["doc_count"]}
            for b in r["aggregations"]["by_hour"]["buckets"]
        ])
    except Exception:
        return jsonify([])

@app.route("/api/logs/top_ips")
def api_logs_top_ips():
    try:
        r = es.search(
            index="soc-logs*",
            size=0,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={"top_ips": {"terms": {"field": "src_ip", "size": 10}}}
        )
        return jsonify([
            {"ip": b["key"], "count": b["doc_count"]}
            for b in r["aggregations"]["top_ips"]["buckets"]
        ])
    except Exception:
        return jsonify([])

@app.route("/api/logs/severity_dist")
def api_logs_severity_dist():
    try:
        r = es.search(
            index="soc-logs*",
            size=0,
            aggs={"by_sev": {"terms": {"field": "severity", "size": 10}}}
        )
        return jsonify({b["key"]: b["doc_count"]
                        for b in r["aggregations"]["by_sev"]["buckets"]})
    except Exception:
        return jsonify({})

@app.route("/api/ia/timeline")
def api_ia_timeline():
    try:
        r = es.search(
            index="soc-anomalies",
            size=0,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={"by_hour": {"date_histogram": {
                "field": "@timestamp", "calendar_interval": "1h"
            }}}
        )
        return jsonify([
            {"time": b["key_as_string"], "count": b["doc_count"]}
            for b in r["aggregations"]["by_hour"]["buckets"]
        ])
    except Exception:
        return jsonify([])

@app.route("/api/ssh/details")
@require_auth
def api_ssh_details():
    """Données détaillées SSH failed pour la page d'accueil."""
    try:
        total    = es_count("soc-logs*", {"term": {"tags": "ssh_failed"}})
        last_1h  = es_count("soc-logs*", {"bool": {"must": [
            {"term":  {"tags": "ssh_failed"}},
            {"range": {"@timestamp": {"gte": "now-1h"}}}
        ]}})
        last_10m = es_count("soc-logs*", {"bool": {"must": [
            {"term":  {"tags": "ssh_failed"}},
            {"range": {"@timestamp": {"gte": "now-10m"}}}
        ]}})
        r = es.search(index="soc-logs*", size=0,
            query={"bool": {"must": [
                {"term":  {"tags": "ssh_failed"}},
                {"range": {"@timestamp": {"gte": "now-24h"}}}
            ]}},
            aggs={
                "top_ips":   {"terms": {"field": "src_ip",   "size": 8}},
                "top_users": {"terms": {"field": "ssh_user", "size": 8}},
                "over_time": {"date_histogram": {
                    "field": "@timestamp", "fixed_interval": "5m",
                    "min_doc_count": 0,
                    "extended_bounds": {"min": "now-1h", "max": "now"}
                }},
            })
        top_ips   = [{"ip": b["key"], "count": b["doc_count"]}
                     for b in r["aggregations"]["top_ips"]["buckets"] if b["key"]]
        top_users = [{"user": b["key"], "count": b["doc_count"]}
                     for b in r["aggregations"]["top_users"]["buckets"] if b["key"]]
        timeline  = [{"ts": b["key_as_string"][:16], "count": b["doc_count"]}
                     for b in r["aggregations"]["over_time"]["buckets"]]
        r2 = es.search(index="soc-logs*", size=15,
            query={"bool": {"must": [
                {"term":  {"tags": "ssh_failed"}},
                {"range": {"@timestamp": {"gte": "now-30m"}}}
            ]}},
            sort=[{"@timestamp": {"order": "desc"}}],
            _source=["@timestamp", "src_ip", "ssh_user", "message", "severity"])
        recent = [{
            "ts":      str(h["_source"].get("@timestamp", ""))[:19].replace("T", " "),
            "ip":      h["_source"].get("src_ip", ""),
            "user":    h["_source"].get("ssh_user", ""),
            "msg":     str(h["_source"].get("message", ""))[-80:],
            "severity":h["_source"].get("severity", "medium"),
        } for h in r2["hits"]["hits"]]
        return jsonify({
            "total": total, "last_1h": last_1h, "last_10m": last_10m,
            "rate_per_min": round(last_10m / 10, 1),
            "top_ips": top_ips, "top_users": top_users,
            "timeline": timeline, "recent": recent,
        })
    except Exception as e:
        return jsonify({"error": str(e), "total": 0, "last_1h": 0, "last_10m": 0,
                        "rate_per_min": 0, "top_ips": [], "top_users": [], "timeline": [], "recent": []})


@app.route("/api/models/metrics")
@require_level("L2")
def api_models_metrics():
    """Métriques en temps réel de chaque modèle ML/DL/LLM."""
    import pickle

    result = {}

    # ── Random Forest ──────────────────────────────────────────────────────────
    try:
        with open(os.path.join(os.path.dirname(__file__), "rf_model.pkl"), "rb") as f:
            rf_data = pickle.load(f)
        m = rf_data.get("metrics", {})
        rf_24h = es.search(index="soc-rf-anomalies", size=0,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={"avg": {"avg": {"field": "anomaly_score"}},
                  "critical": {"filter": {"range": {"anomaly_score": {"gte": 0.85}}}}})
        ag = rf_24h["aggregations"]
        result["rf"] = {
            "name": "Random Forest", "type": "supervisé", "color": "green",
            "precision": round(m.get("precision", 0), 3),
            "recall":    round(m.get("recall", 0), 3),
            "f1":        round(m.get("f1", 0), 3),
            "trained_at": rf_data.get("trained_at", "")[:10],
            "alerts_24h": rf_24h["hits"]["total"]["value"],
            "avg_score":  round(ag["avg"]["value"] or 0, 3),
            "critical_24h": ag["critical"]["doc_count"],
            "threshold": 0.55,
            "description": "Entraîné sur logs labellisés (IPs attaquantes connues + verdicts Ollama). Détecte par pattern de logs.",
        }
    except Exception as e:
        result["rf"] = {"name": "Random Forest", "error": str(e)}

    # ── Isolation Forest ───────────────────────────────────────────────────────
    try:
        if_24h = es.search(index="soc-anomalies", size=0,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={"avg": {"avg": {"field": "anomaly_score"}},
                  "critical": {"filter": {"range": {"anomaly_score": {"gte": 0.7}}}},
                  "top_ips": {"terms": {"field": "src_ip", "size": 3}}})
        ag = if_24h["aggregations"]
        result["if"] = {
            "name": "Isolation Forest", "type": "non-supervisé", "color": "blue",
            "precision": None, "recall": None, "f1": None,
            "alerts_24h": if_24h["hits"]["total"]["value"],
            "avg_score":  round(ag["avg"]["value"] or 0, 3),
            "critical_24h": ag["critical"]["doc_count"],
            "threshold": 0.25,
            "top_ips": [b["key"] for b in ag["top_ips"]["buckets"] if b["key"]],
            "description": "Non-supervisé — apprend la normalité et isole les points aberrants. Pas d'étiquettes nécessaires.",
        }
    except Exception as e:
        result["if"] = {"name": "Isolation Forest", "error": str(e)}

    # ── Autoencoder DL ─────────────────────────────────────────────────────────
    try:
        with open(os.path.join(os.path.dirname(__file__), "autoencoder_threshold.json")) as f:
            dl_thr = json.load(f)
        dl_24h = es.search(index="soc-dl-anomalies", size=0,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={"avg": {"avg": {"field": "anomaly_score"}},
                  "critical": {"filter": {"range": {"anomaly_score": {"gte": 0.7}}}}})
        ag = dl_24h["aggregations"]
        result["dl"] = {
            "name": "Autoencoder DL", "type": "deep learning", "color": "orange",
            "precision": None, "recall": None, "f1": None,
            "alerts_24h": dl_24h["hits"]["total"]["value"],
            "avg_score":  round(ag["avg"]["value"] or 0, 3),
            "critical_24h": ag["critical"]["doc_count"],
            "threshold": round(dl_thr.get("threshold", 0.05), 6),
            "train_mean": round(dl_thr.get("train_mean", 0), 6),
            "description": "Autoencoder MSE — reconstruit les entrées normales, erreur élevée = anomalie. Architecture: n→16→8→16→n.",
        }
    except Exception as e:
        result["dl"] = {"name": "Autoencoder DL", "error": str(e)}

    # ── Ensemble ───────────────────────────────────────────────────────────────
    try:
        ens_24h = es.search(index="soc-ensemble-anomalies", size=0,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={"avg_score": {"avg": {"field": "ensemble_score"}},
                  "avg_votes": {"avg": {"field": "votes"}},
                  "votes_dist": {"terms": {"field": "votes", "size": 5}},
                  "if_contrib": {"avg": {"field": "if_score"}},
                  "rf_contrib": {"avg": {"field": "rf_score"}},
                  "dl_contrib": {"avg": {"field": "dl_score"}}})
        ag = ens_24h["aggregations"]
        result["ensemble"] = {
            "name": "Ensemble", "type": "vote pondéré", "color": "red",
            "alerts_24h": ens_24h["hits"]["total"]["value"],
            "avg_score":  round(ag["avg_score"]["value"] or 0, 3),
            "avg_votes":  round(ag["avg_votes"]["value"] or 0, 1),
            "votes_dist": {str(b["key"]): b["doc_count"] for b in ag["votes_dist"]["buckets"]},
            "avg_if_contrib": round(ag["if_contrib"]["value"] or 0, 3),
            "avg_rf_contrib": round(ag["rf_contrib"]["value"] or 0, 3),
            "avg_dl_contrib": round(ag["dl_contrib"]["value"] or 0, 3),
            "weights": {"IF": 0.30, "RF": 0.35, "DL": 0.20, "Rate": 0.15},
            "threshold": 0.28, "min_votes": 2,
            "description": "Vote IF×0.30 + RF×0.35 + DL×0.20 + Rate×0.15. Alerte si ≥2/4 votes. Élimine les FP isolés.",
        }
    except Exception as e:
        result["ensemble"] = {"name": "Ensemble", "error": str(e)}

    # ── LLM Ollama ─────────────────────────────────────────────────────────────
    try:
        mem_path = os.path.join(os.path.dirname(__file__), "llm_memory.json")
        try:
            with open(mem_path) as f:
                memory = json.load(f)
            mem_count = len(memory)
        except Exception:
            mem_count = 0

        analyzed = es.count(index="soc-incidents", query={"exists": {"field": "ai_analysis"}})["count"]
        tp = es.count(index="soc-incidents", query={"term": {"ai_analysis.verdict.keyword": "true_positive"}})["count"]
        fp = es.count(index="soc-incidents", query={"term": {"ai_analysis.verdict.keyword": "false_positive"}})["count"]
        unc = es.count(index="soc-incidents", query={"term": {"ai_analysis.verdict.keyword": "uncertain"}})["count"]
        llama3_real = es.count(index="soc-incidents", query={"term": {"ai_analysis.model.keyword": "llama3"}})["count"]

        r = es.search(index="soc-incidents", size=0,
            query={"exists": {"field": "ai_analysis.confidence"}},
            aggs={"avg_conf": {"avg": {"field": "ai_analysis.confidence"}}})
        avg_conf = round(r["aggregations"]["avg_conf"]["value"] or 0, 3)

        result["llm"] = {
            "name": "Ollama llama3", "type": "LLM analyse", "color": "purple",
            "analyzed": analyzed, "true_positive": tp, "false_positive": fp,
            "uncertain": unc, "llama3_real": llama3_real,
            "fallback": analyzed - llama3_real,
            "avg_confidence": avg_conf,
            "memory_examples": mem_count,
            "llm_labels_for_rf": tp + fp,
            "description": "Analyse contextuelle des incidents. Few-shot learning — mémorise ses meilleures analyses pour s'améliorer.",
        }
    except Exception as e:
        result["llm"] = {"name": "Ollama llama3", "error": str(e)}

    return jsonify(result)


@app.route("/api/home/services")
@require_auth
def api_home_services():
    """Status des services et détecteurs pour la page d'accueil."""
    import subprocess
    def check_proc(p):
        try:
            return bool(subprocess.run(["pgrep", "-f", p], capture_output=True).stdout.strip())
        except Exception:
            return False
    def check_port(p):
        import socket
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=1):
                return True
        except Exception:
            return False
    services = {
        "elasticsearch": {"up": check_port(9200),  "label": "Elasticsearch",    "icon": "fa-database",       "color": "yellow"},
        "logstash":      {"up": check_port(5044),  "label": "Logstash",         "icon": "fa-filter",         "color": "orange"},
        "kibana":        {"up": check_port(5601),  "label": "Kibana",           "icon": "fa-chart-bar",      "color": "muted"},
        "flask":         {"up": check_port(5000),  "label": "Flask SOC",        "icon": "fa-shield-alt",     "color": "green"},
        "ollama":        {"up": check_port(11434), "label": "Ollama gemma2:2b",  "icon": "fa-robot",          "color": "blue"},
        "ia_if":         {"up": check_proc("ia_detector"),       "label": "Isolation Forest", "icon": "fa-tree",           "color": "purple"},
        "ia_rf":         {"up": check_proc("rf_detector"),       "label": "Random Forest",    "icon": "fa-check-double",   "color": "green"},
        "ia_dl":         {"up": check_proc("dl_detector"),       "label": "Autoencoder DL",   "icon": "fa-project-diagram","color": "orange"},
        "ia_rate":       {"up": check_proc("rate_detector"),     "label": "Rate Detector",    "icon": "fa-tachometer-alt", "color": "yellow"},
        "ia_ensemble":   {"up": check_proc("ensemble_detector"), "label": "Ensemble",         "icon": "fa-vote-yea",       "color": "red"},
    }
    # Filebeat health: logs received in last 5 minutes
    try:
        fb_count = es.count(index="soc-logs*",
                            query={"range": {"@timestamp": {"gte": "now-5m"}}})["count"]
        services["filebeat"] = {"up": fb_count > 0, "label": f"Filebeat ({fb_count} logs/5min)",
                                "icon": "fa-file-import", "color": "green"}
    except Exception:
        services["filebeat"] = {"up": False, "label": "Filebeat", "icon": "fa-file-import", "color": "green"}
    up_count = sum(1 for s in services.values() if s["up"])
    return jsonify({"services": services, "up": up_count, "total": len(services)})


@app.route("/api/analytics/overview")
def api_analytics_overview():
    ssh_failed  = es_count("soc-logs*", {"term": {"tags": "ssh_failed"}})
    ia_critical = es_count("soc-anomalies", {"range": {"anomaly_score": {"gte": 0.7}}})
    cve_count   = es_count("soc-cve-alerts")

    # Log types breakdown (24h)
    log_types = []
    try:
        r = es.search(index="soc-logs*", size=0,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={"by_type": {"terms": {"field": "log_type", "size": 10}}})
        log_types = [{"key": b["key"], "doc_count": b["doc_count"]}
                     for b in r["aggregations"]["by_type"]["buckets"]]
    except Exception:
        pass

    # Top IPs (24h)
    top_ips = []
    try:
        r = es.search(index="soc-logs*", size=0,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={"top_ips": {"terms": {"field": "src_ip", "size": 10}}})
        top_ips = [{"key": b["key"], "doc_count": b["doc_count"]}
                   for b in r["aggregations"]["top_ips"]["buckets"]]
    except Exception:
        pass

    # Recent incidents (last 20)
    recent_incidents = []
    try:
        r = es.search(index="soc-incidents", size=20,
            query={"match_all": {}},
            sort=[{"created_at": {"order": "desc"}}])
        recent_incidents = [{"id": h["_id"], **h["_source"]} for h in r["hits"]["hits"]]
    except Exception:
        pass

    return jsonify({
        "risk_score":        compute_risk_score(ssh_failed, ia_critical, cve_count),
        "total_logs":        es_count("soc-logs*"),
        "logs_24h":          es_count("soc-logs*", {"range": {"@timestamp": {"gte": "now-24h"}}}),
        "ssh_failed":        ssh_failed,
        "ids_alerts":        es_count("soc-logs*", {"term": {"tags.keyword": "ids_alert"}}),
        "anomalies":         es_count("soc-anomalies"),
        "anomalies_critical": ia_critical,
        "cve_count":         cve_count,
        "incidents_open":    es_count("soc-incidents", {"term": {"status.keyword": "awaiting_action"}}),
        "log_types":         log_types,
        "top_ips":           top_ips,
        "recent_incidents":  recent_incidents,
    })

@app.route("/api/health")
def api_health():
    status = {}
    # Elasticsearch
    try:
        info = es.info()
        status["elasticsearch"] = {"ok": True, "version": info["version"]["number"]}
    except Exception as e:
        status["elasticsearch"] = {"ok": False, "error": str(e)}

    # Indices
    for idx in ["soc-logs*", "soc-anomalies", "soc-dl-anomalies", "soc-incidents", "soc-cve-alerts"]:
        try:
            count = es.count(index=idx)["count"]
            status[idx.replace("*", "all")] = {"ok": True, "count": count}
        except Exception:
            status[idx.replace("*", "all")] = {"ok": False, "count": 0}

    # Processus détecteurs
    import subprocess as sp
    for proc in ["ia_detector", "dl_detector", "rate_detector", "cve_scanner"]:
        result = sp.run(["pgrep", "-f", proc], capture_output=True)
        status[proc] = {"running": result.returncode == 0}

    overall = all(v.get("ok", True) for k, v in status.items() if "ok" in v)
    return jsonify({"healthy": overall, "components": status,
                    "timestamp": datetime.utcnow().isoformat() + "Z"})


@app.route("/api/dl_anomalies")
def api_dl_anomalies():
    anomalies = es_search("soc-dl-anomalies", size=100)
    total = es_count("soc-dl-anomalies")
    return jsonify({"total": total, "anomalies": anomalies})


@app.route("/api/compare")
def api_compare():
    """Retourne les métriques des deux modèles pour la page de comparaison."""
    window = request.args.get("window", "24h")

    # Isolation Forest
    if_total    = es_count("soc-anomalies", {"range": {"@timestamp": {"gte": f"now-{window}"}}})
    if_critical = es_count("soc-anomalies", {"bool": {"must": [
        {"range": {"@timestamp": {"gte": f"now-{window}"}}},
        {"range": {"anomaly_score": {"gte": 0.7}}}
    ]}})
    if_recent   = es_search("soc-anomalies",
                            query={"range": {"@timestamp": {"gte": f"now-{window}"}}},
                            size=20, sort=[{"@timestamp": {"order": "desc"}}])

    # Autoencoder
    dl_total    = es_count("soc-dl-anomalies", {"range": {"@timestamp": {"gte": f"now-{window}"}}})
    dl_critical = es_count("soc-dl-anomalies", {"bool": {"must": [
        {"range": {"@timestamp": {"gte": f"now-{window}"}}},
        {"range": {"anomaly_score": {"gte": 0.7}}}
    ]}})
    dl_recent   = es_search("soc-dl-anomalies",
                            query={"range": {"@timestamp": {"gte": f"now-{window}"}}},
                            size=20, sort=[{"@timestamp": {"order": "desc"}}])

    # Score moyen
    def avg_score(index, window_str):
        try:
            r = es.search(index=index, size=0,
                          query={"range": {"@timestamp": {"gte": f"now-{window_str}"}}},
                          aggs={"avg": {"avg": {"field": "anomaly_score"}}})
            return round(r["aggregations"]["avg"]["value"] or 0, 3)
        except Exception:
            return 0

    # Timeline comparatif
    def timeline(index, window_str):
        try:
            r = es.search(index=index, size=0,
                          query={"range": {"@timestamp": {"gte": f"now-{window_str}"}}},
                          aggs={"by_hour": {"date_histogram": {
                              "field": "@timestamp", "calendar_interval": "1h"
                          }}})
            return [{"time": b["key_as_string"], "count": b["doc_count"]}
                    for b in r["aggregations"]["by_hour"]["buckets"]]
        except Exception:
            return []

    return jsonify({
        "window": window,
        "isolation_forest": {
            "total": if_total, "critical": if_critical,
            "avg_score": avg_score("soc-anomalies", window),
            "timeline": timeline("soc-anomalies", window),
            "recent": if_recent
        },
        "autoencoder": {
            "total": dl_total, "critical": dl_critical,
            "avg_score": avg_score("soc-dl-anomalies", window),
            "timeline": timeline("soc-dl-anomalies", window),
            "recent": dl_recent
        }
    })


@app.route("/compare")
@require_level("L2")
def compare_page():
    return render_template("compare.html")


@app.route("/dl")
@require_level("L2")
def dl_page():
    return render_template("dl.html")


# ─── LOGS API (paginated + filtered) ─────────────────────────────────────────

@app.route("/api/logs")
def api_logs():
    page      = max(1, int(request.args.get("page", 1)))
    size      = min(100, max(10, int(request.args.get("size", 25))))
    src_ip    = request.args.get("src_ip", "").strip()
    severity  = request.args.get("severity", "").strip()
    log_type  = request.args.get("log_type", "").strip()
    tag       = request.args.get("tag", "").strip()
    q         = request.args.get("q", "").strip()
    date_from = request.args.get("date_from", "now-24h")
    date_to   = request.args.get("date_to", "now")
    sort_field = request.args.get("sort", "@timestamp")
    sort_order = request.args.get("order", "desc")

    filters = [{"range": {"@timestamp": {"gte": date_from, "lte": date_to}}}]
    if src_ip:   filters.append({"term": {"src_ip": src_ip}})
    if severity: filters.append({"term": {"severity": severity}})
    if log_type: filters.append({"term": {"log_type": log_type}})
    if tag:      filters.append({"term": {"tags": tag}})

    query = {"bool": {"filter": filters}}
    if q:
        query["bool"]["must"] = [{"multi_match": {"query": q, "fields": ["message", "ssh_user", "src_ip"]}}]

    try:
        result = es.search(
            index="soc-logs*",
            query=query,
            sort=[{sort_field: {"order": sort_order}}],
            from_=(page - 1) * size,
            size=size,
            track_total_hits=True
        )
        hits  = [{"_id": h["_id"], "_index": h["_index"], **h["_source"]} for h in result["hits"]["hits"]]
        total = result["hits"]["total"]["value"]
    except Exception as e:
        hits, total = [], 0

    return jsonify({
        "hits":  hits,
        "total": total,
        "page":  page,
        "size":  size,
        "pages": max(1, (total + size - 1) // size)
    })


@app.route("/api/logs/live")
def api_logs_live():
    since    = request.args.get("since", "now-1m")
    size     = min(50, int(request.args.get("size", 20)))
    log_type = request.args.get("log_type", "").strip()
    filters  = [{"range": {"@timestamp": {"gt": since}}}]
    if log_type:
        filters.append({"term": {"log_type.keyword": log_type}})
    try:
        r = es.search(
            index="soc-logs*",
            query={"bool": {"filter": filters}},
            sort=[{"@timestamp": {"order": "desc"}}],
            size=size,
            track_total_hits=True
        )
        hits  = [{"_id": h["_id"], "_index": h["_index"], **h["_source"]} for h in r["hits"]["hits"]]
        total = r["hits"]["total"]["value"]
        latest_ts = hits[0]["@timestamp"] if hits else since
    except Exception:
        hits, total, latest_ts = [], 0, since
    return jsonify({"hits": hits, "count": total, "latest_ts": latest_ts})


@app.route("/api/logs/export")
def api_logs_export():
    src_ip    = request.args.get("src_ip", "").strip()
    severity  = request.args.get("severity", "").strip()
    log_type  = request.args.get("log_type", "").strip()
    tag       = request.args.get("tag", "").strip()
    q         = request.args.get("q", "").strip()
    date_from = request.args.get("date_from", "now-24h")
    date_to   = request.args.get("date_to", "now")

    filters = [{"range": {"@timestamp": {"gte": date_from, "lte": date_to}}}]
    if src_ip:   filters.append({"term": {"src_ip": src_ip}})
    if severity: filters.append({"term": {"severity": severity}})
    if log_type: filters.append({"term": {"log_type": log_type}})
    if tag:      filters.append({"term": {"tags": tag}})

    query = {"bool": {"filter": filters}}
    if q:
        query["bool"]["must"] = [{"multi_match": {"query": q, "fields": ["message", "ssh_user", "src_ip"]}}]

    try:
        result = es.search(index="soc-logs*", query=query,
                           sort=[{"@timestamp": {"order": "desc"}}], size=5000)
        hits = [h["_source"] for h in result["hits"]["hits"]]
    except:
        hits = []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["@timestamp", "log_type", "severity", "src_ip", "ssh_user", "hostname", "tags", "message"])
    for h in hits:
        tags = ",".join(h.get("tags", [])) if isinstance(h.get("tags"), list) else str(h.get("tags", ""))
        writer.writerow([
            h.get("@timestamp", ""), h.get("log_type", ""), h.get("severity", ""),
            h.get("src_ip", ""), h.get("ssh_user", ""), h.get("hostname", ""),
            tags, (h.get("message", "") or "")[:200]
        ])
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="soc-logs-{datetime.utcnow().strftime("%Y%m%d-%H%M")}.csv"'
    return resp


# ─── ANOMALIES API (IF + DL, paginated + filtered) ───────────────────────────

def _anomaly_query(request, index):
    page      = max(1, int(request.args.get("page", 1)))
    size      = min(100, max(10, int(request.args.get("size", 25))))
    min_score = float(request.args.get("min_score", 0))
    max_score = float(request.args.get("max_score", 1))
    src_ip    = request.args.get("src_ip", "").strip()
    log_type  = request.args.get("log_type", "").strip()
    severity  = request.args.get("severity", "").strip()
    date_from = request.args.get("date_from", "now-24h")
    date_to   = request.args.get("date_to", "now")

    filters = [
        {"range": {"@timestamp":    {"gte": date_from, "lte": date_to}}},
        {"range": {"anomaly_score": {"gte": min_score, "lte": max_score}}}
    ]
    if src_ip:   filters.append({"term": {"src_ip": src_ip}})
    if log_type: filters.append({"term": {"log_type": log_type}})
    if severity: filters.append({"term": {"severity": severity}})

    query = {"bool": {"filter": filters}}
    try:
        result = es.search(
            index=index, query=query,
            sort=[{"@timestamp": {"order": "desc"}}],
            from_=(page - 1) * size, size=size, track_total_hits=True
        )
        hits  = [{"_id": h["_id"], **h["_source"]} for h in result["hits"]["hits"]]
        total = result["hits"]["total"]["value"]
    except:
        hits, total, page, size = [], 0, 1, 25

    return jsonify({
        "hits": hits, "total": total,
        "page": page, "size": size,
        "pages": max(1, (total + size - 1) // size)
    })


@app.route("/api/anomalies")
def api_anomalies():
    return _anomaly_query(request, "soc-anomalies")


@app.route("/api/dl_anomalies_paged")
def api_dl_anomalies_paged():
    return _anomaly_query(request, "soc-dl-anomalies")


@app.route("/api/rf_anomalies")
def api_rf_anomalies():
    return _anomaly_query(request, "soc-rf-anomalies")


MODEL_INDEX_MAP = {
    "if":  "soc-anomalies",
    "dl":  "soc-dl-anomalies",
    "rf":  "soc-rf-anomalies",
}

@app.route("/api/anomalies/model")
def api_anomalies_model():
    """Endpoint unifié : ?model=if|dl|rf"""
    model = request.args.get("model", "if").lower()
    index = MODEL_INDEX_MAP.get(model, "soc-anomalies")
    return _anomaly_query(request, index)


@app.route("/api/anomalies/export")
def api_anomalies_export():
    index    = request.args.get("model", "if")
    idx      = "soc-anomalies" if index == "if" else "soc-dl-anomalies"
    date_from = request.args.get("date_from", "now-24h")
    try:
        result = es.search(index=idx,
                           query={"range": {"@timestamp": {"gte": date_from}}},
                           sort=[{"@timestamp": {"order": "desc"}}], size=5000)
        hits = [h["_source"] for h in result["hits"]["hits"]]
    except:
        hits = []
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["@timestamp", "anomaly_score", "severity", "src_ip", "log_type", "ssh_user", "reconstruction_loss"])
    for h in hits:
        writer.writerow([
            h.get("@timestamp", ""), h.get("anomaly_score", ""), h.get("severity", ""),
            h.get("src_ip", ""), h.get("log_type", ""), h.get("ssh_user", ""),
            h.get("reconstruction_loss", "")
        ])
    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="anomalies-{index}-{datetime.utcnow().strftime("%Y%m%d-%H%M")}.csv"'
    return resp


# ─── LABEL (TP/FP/Benign) ────────────────────────────────────────────────────

_retrain_lock  = threading.Lock()
_labels_at_last_retrain = [0]   # mutable pour closure thread
RETRAIN_EVERY_N_LABELS  = 10    # déclenche RF+meta après N nouveaux labels


def _bg_retrain_rf():
    """Réentraîne RF + meta-learner en arrière-plan après de nouveaux labels."""
    if not _retrain_lock.acquire(blocking=False):
        return  # déjà en cours
    try:
        import sys, os
        venv = os.path.join(os.path.dirname(__file__), "venv", "bin", "python3")
        soc  = os.path.dirname(os.path.abspath(__file__))
        app.logger.info("[AutoRetrain] Réentraînement RF déclenché par nouveaux labels")
        r = subprocess.run(
            [venv, os.path.join(soc, "rf_detector.py"), "--train-only"],
            capture_output=True, text=True, timeout=180, cwd=soc
        )
        if r.returncode == 0:
            app.logger.info("[AutoRetrain] RF OK")
        else:
            app.logger.warning(f"[AutoRetrain] RF stderr: {r.stderr[-300:]}")
        # Meta-learner ensuite
        import importlib, meta_learner
        importlib.reload(meta_learner)
        ok = meta_learner.train()
        app.logger.info(f"[AutoRetrain] Meta-learner {'OK' if ok else 'skip (données insuffisantes)'}")
    except Exception as e:
        app.logger.error(f"[AutoRetrain] Erreur: {e}")
    finally:
        _retrain_lock.release()


@app.route("/api/anomaly/label", methods=["POST"])
def api_anomaly_label():
    data    = request.json or {}
    verdict = data.get("verdict", "")
    if verdict not in ("TP", "FP", "Benign"):
        return jsonify({"error": "verdict must be TP, FP or Benign"}), 400
    doc = {
        "@timestamp":        datetime.utcnow().isoformat() + "Z",
        "model":             data.get("model", "isolation_forest"),
        "src_ip":            data.get("src_ip", ""),
        "verdict":           verdict,
        "anomaly_timestamp": data.get("anomaly_ts", ""),
    }
    try:
        es.index(index="soc-anomaly-labels", document=doc)
        # Déclencher auto-retrain si seuil atteint
        try:
            total_labels = es.count(index="soc-anomaly-labels")["count"]
            if total_labels - _labels_at_last_retrain[0] >= RETRAIN_EVERY_N_LABELS:
                _labels_at_last_retrain[0] = total_labels
                t = threading.Thread(target=_bg_retrain_rf, daemon=True)
                t.start()
                return jsonify({"status": "labeled", "retrain": "triggered"}), 201
        except Exception:
            pass
        return jsonify({"status": "labeled"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── METRICS (TP/FP/FN/Precision/Recall/F1) ──────────────────────────────────

def _estimate_fn(anomaly_index, window):
    """Estimate FN: 10-min windows with ssh_failed>=10 but no anomaly detected."""
    try:
        r_a = es.search(index="soc-logs*", size=0,
            query={"bool": {"filter": [
                {"range": {"@timestamp": {"gte": f"now-{window}"}}},
                {"term":  {"tags.keyword": "ssh_failed"}}
            ]}},
            aggs={"w": {"date_histogram": {"field": "@timestamp", "fixed_interval": "10m"}}})
        attack_w = {b["key"] for b in r_a["aggregations"]["w"]["buckets"] if b["doc_count"] >= 10}

        r_d = es.search(index=anomaly_index, size=0,
            query={"range": {"@timestamp": {"gte": f"now-{window}"}}},
            aggs={"w": {"date_histogram": {"field": "@timestamp", "fixed_interval": "10m"}}})
        detect_w = {b["key"] for b in r_d["aggregations"]["w"]["buckets"] if b["doc_count"] > 0}

        return len(attack_w - detect_w)
    except:
        return 0


def _compute_metrics(anomaly_index, model_name, window):
    total = es_count(anomaly_index, {"range": {"@timestamp": {"gte": f"now-{window}"}}})

    try:
        r = es.search(index="soc-anomaly-labels", size=0,
            query={"bool": {"filter": [
                {"term":  {"model.keyword": model_name}},
                {"range": {"@timestamp": {"gte": f"now-{window}"}}}
            ]}},
            aggs={"v": {"terms": {"field": "verdict.keyword"}}})
        lbl = {b["key"]: b["doc_count"] for b in r["aggregations"]["v"]["buckets"]}
    except:
        lbl = {}

    tp     = lbl.get("TP", 0)
    fp     = lbl.get("FP", 0)
    benign = lbl.get("Benign", 0)
    fn     = _estimate_fn(anomaly_index, window)

    precision = round(tp / (tp + fp), 3)       if (tp + fp) > 0  else None
    recall    = round(tp / (tp + fn), 3)        if (tp + fn) > 0  else None
    f1        = round(2 * precision * recall / (precision + recall), 3) \
                if (precision and recall)        else None

    return jsonify({
        "total": total, "labeled": tp + fp + benign,
        "tp": tp, "fp": fp, "fn": fn, "benign": benign,
        "precision": precision, "recall": recall, "f1": f1
    })


@app.route("/api/ia/metrics")
def api_ia_metrics():
    return _compute_metrics("soc-anomalies", "isolation_forest",
                            request.args.get("window", "24h"))


@app.route("/api/dl/metrics")
def api_dl_metrics():
    resp = _compute_metrics("soc-dl-anomalies", "autoencoder",
                            request.args.get("window", "24h"))
    # Append current autoencoder threshold
    threshold = None
    threshold_path = os.path.join(os.path.dirname(__file__), "autoencoder_threshold.json")
    try:
        import json as _json
        with open(threshold_path) as f:
            threshold = _json.load(f).get("threshold")
    except Exception:
        pass
    data = resp.get_json()
    data["threshold"] = threshold
    return jsonify(data)


# ─── OVERLAP IF vs DL ────────────────────────────────────────────────────────

@app.route("/api/compare/overlap")
def api_compare_overlap():
    window = request.args.get("window", "24h")
    try:
        def get_windows(index):
            r = es.search(index=index, size=0,
                query={"range": {"@timestamp": {"gte": f"now-{window}"}}},
                aggs={"w5": {"date_histogram": {"field": "@timestamp", "fixed_interval": "5m"},
                      "aggs": {"ips": {"terms": {"field": "src_ip", "size": 20}}}}})
            s = set()
            for b in r["aggregations"]["w5"]["buckets"]:
                for ib in b["ips"]["buckets"]:
                    s.add((b["key"], ib["key"]))
            return s

        ifw = get_windows("soc-anomalies")
        dlw = get_windows("soc-dl-anomalies")
        return jsonify({
            "both":    len(ifw & dlw),
            "if_only": len(ifw - dlw),
            "dl_only": len(dlw - ifw),
            "total_if_windows": len(ifw),
            "total_dl_windows": len(dlw)
        })
    except Exception as e:
        return jsonify({"both": 0, "if_only": 0, "dl_only": 0, "error": str(e)})


# ─── INCIDENTS LIVE (polling temps réel) ─────────────────────────────────────

@app.route("/api/incidents/live")
def api_incidents_live():
    """Retourne les N derniers incidents — endpoint léger pour polling temps réel."""
    try:
        since = request.args.get("since", "")
        size  = int(request.args.get("size", 20))
        must  = []
        if since:
            must.append({"range": {"created_at": {"gt": since}}})
        query = {"bool": {"must": must}} if must else {"match_all": {}}
        r = es.search(
            index="soc-incidents",
            query=query,
            size=size,
            sort=[{"created_at": {"order": "desc"}}],
            source=["title","severity","status","verdict","assigned_to","level",
                    "src_ip","type","created_at","updated_at","score","description"]
        )
        incidents = [{"id": h["_id"], **h["_source"]} for h in r["hits"]["hits"]]
        latest_ts = incidents[0]["created_at"] if incidents else since
        return jsonify({"incidents": incidents, "latest_ts": latest_ts, "count": len(incidents)})
    except Exception as e:
        return jsonify({"incidents": [], "latest_ts": since, "count": 0, "error": str(e)})


# ─── INCIDENTS STATS ─────────────────────────────────────────────────────────

@app.route("/api/incidents/stats")
def api_incidents_stats():
    try:
        r = es.search(index="soc-incidents", size=0, aggs={
            "by_status":  {"terms": {"field": "status"}},
            "by_severity":{"terms": {"field": "severity"}},
            "by_verdict": {"terms": {"field": "verdict.keyword"}}
        })
        a = r["aggregations"]
        status_map  = {b["key"]: b["doc_count"] for b in a["by_status"]["buckets"]}
        verdict_map = {b["key"]: b["doc_count"] for b in a["by_verdict"]["buckets"]}
        tp = verdict_map.get("true_positive", 0) + verdict_map.get("TP", 0)
        fp = verdict_map.get("false_positive", 0) + verdict_map.get("FP", 0)
        total_labeled = tp + fp + verdict_map.get("benign", 0) + verdict_map.get("Benign", 0)
        total       = es_count("soc-incidents")
        awaiting    = status_map.get("awaiting_action", 0)
        in_progress = status_map.get("in_progress", 0)
        closed      = status_map.get("closed", 0)
        total_labeled = tp + fp + verdict_map.get("benign", 0) + verdict_map.get("Benign", 0)
        tp_rate = round(tp / total_labeled, 3) if total_labeled > 0 else None
        fp_rate = round(fp / total_labeled, 3) if total_labeled > 0 else None
        return jsonify({
            "total":      total,
            "awaiting":   awaiting,
            "open":       awaiting,  # alias
            "in_progress":in_progress,
            "closed":     closed,
            "tp": tp, "fp": fp,
            "tp_rate":    tp_rate,
            "fp_rate":    fp_rate,
            "by_severity":{b["key"]: b["doc_count"] for b in a["by_severity"]["buckets"]}
        })
    except Exception as e:
        return jsonify({"error": str(e), "total": 0, "awaiting": 0, "open": 0, "closed": 0,
                        "tp": 0, "fp": 0, "tp_rate": None, "fp_rate": None})


@app.route("/api/ip/profile/<path:src_ip>")
def api_ip_profile(src_ip):
    """Profil complet d'une IP : stats logs, SSH, HTTP, incidents, timeline."""
    try:
        window = "now-24h"
        base_q = {"bool": {"must": [
            {"term": {"src_ip": src_ip}},
            {"range": {"@timestamp": {"gte": window}}}
        ]}}

        # Counts par type / tag
        r = es.search(index="soc-logs*", size=0, query=base_q, aggs={
            "by_type":    {"terms": {"field": "log_type.keyword",   "size": 10}},
            "by_tag":     {"terms": {"field": "tags",                "size": 10}},
            "by_severity":{"terms": {"field": "severity.keyword",   "size": 6}},
            "timeline":   {"date_histogram": {"field": "@timestamp", "fixed_interval": "10m", "min_doc_count": 0}},
            "ssh_users":  {"terms": {"field": "ssh_user.keyword",   "size": 10}},
            "http_codes": {"terms": {"field": "response.keyword",   "size": 10}},
            "http_paths": {"terms": {"field": "request.keyword",    "size": 5}},
        })
        aggs = r["aggregations"]
        total_logs = r["hits"]["total"]["value"]

        tag_map  = {b["key"]: b["doc_count"] for b in aggs["by_tag"]["buckets"]}
        type_map = {b["key"]: b["doc_count"] for b in aggs["by_type"]["buckets"]}
        sev_map  = {b["key"]: b["doc_count"] for b in aggs["by_severity"]["buckets"]}

        ssh_failed  = tag_map.get("ssh_failed", 0)
        ssh_success = tag_map.get("ssh_success", 0)
        http_errors = tag_map.get("http_error", 0)
        ids_alerts  = tag_map.get("ids_alert", 0)

        timeline = [{"ts": b["key_as_string"], "count": b["doc_count"]}
                    for b in aggs["timeline"]["buckets"][-12:]]

        # Rate /min over last hour
        r1h = es.count(index="soc-logs*", query={"bool": {"must": [
            {"term": {"src_ip": src_ip}},
            {"range": {"@timestamp": {"gte": "now-1h"}}}
        ]}})
        rate = round(r1h["count"] / 60, 1)

        # Incidents pour cette IP
        inc_r = es.search(index="soc-incidents", size=5,
            query={"term": {"src_ip": src_ip}},
            sort=[{"created_at": "desc"}],
            _source=["incident_id", "title", "severity", "status", "llm_verdict", "created_at"])
        incidents = [h["_source"] for h in inc_r["hits"]["hits"]]

        # First/last seen
        first_r = es.search(index="soc-logs*", size=1, query=base_q,
                            sort=[{"@timestamp": "asc"}], _source=["@timestamp"])
        last_r  = es.search(index="soc-logs*", size=1, query=base_q,
                            sort=[{"@timestamp": "desc"}], _source=["@timestamp"])
        first_seen = first_r["hits"]["hits"][0]["_source"]["@timestamp"][:19] if first_r["hits"]["hits"] else None
        last_seen  = last_r["hits"]["hits"][0]["_source"]["@timestamp"][:19]  if last_r["hits"]["hits"] else None

        return jsonify({
            "src_ip": src_ip,
            "total_logs": total_logs,
            "ssh_failed": ssh_failed,
            "ssh_success": ssh_success,
            "http_errors": http_errors,
            "ids_alerts": ids_alerts,
            "rate_per_min": rate,
            "by_type": type_map,
            "by_severity": sev_map,
            "ssh_users": [{"user": b["key"], "count": b["doc_count"]} for b in aggs["ssh_users"]["buckets"]],
            "http_paths": [{"path": b["key"], "count": b["doc_count"]} for b in aggs["http_paths"]["buckets"]],
            "timeline": timeline,
            "incidents": incidents,
            "first_seen": first_seen,
            "last_seen":  last_seen,
        })
    except Exception as e:
        return jsonify({"error": str(e), "src_ip": src_ip, "total_logs": 0})


@app.route("/api/compare/models")
def api_compare_models():
    """Compare IF vs RF : scores, alertes, métriques du modèle RF."""
    window = request.args.get("window", "24h")
    try:
        def _count(index, q=None):
            try:
                base = {"range": {"@timestamp": {"gte": f"now-{window}"}}}
                query = {"bool": {"must": [base] + ([q] if q else [])}} if q else base
                return es.count(index=index, query=query)["count"]
            except:
                return 0

        def _avg_score(index, field="anomaly_score"):
            try:
                r = es.search(index=index, size=0,
                    query={"range": {"@timestamp": {"gte": f"now-{window}"}}},
                    aggs={"avg": {"avg": {"field": field}},
                          "max": {"max": {"field": field}}}
                )
                return {
                    "avg": round(r["aggregations"]["avg"]["value"] or 0, 3),
                    "max": round(r["aggregations"]["max"]["value"] or 0, 3),
                }
            except:
                return {"avg": 0, "max": 0}

        if_stats = _avg_score("soc-anomalies")
        rf_stats = _avg_score("soc-rf-anomalies")

        # Charger métriques RF depuis le pickle
        rf_metrics = {}
        rf_model_path = os.path.join(os.path.dirname(__file__), "rf_model.pkl")
        if os.path.exists(rf_model_path):
            import pickle
            try:
                with open(rf_model_path, "rb") as f:
                    data = pickle.load(f)
                rf_metrics = data.get("metrics", {})
                rf_metrics["trained_at"] = data.get("trained_at", "")[:10]
            except:
                pass

        return jsonify({
            "window": window,
            "if": {
                "name": "Isolation Forest",
                "type": "unsupervised",
                "index": "soc-anomalies",
                "alerts": _count("soc-anomalies"),
                "avg_score": if_stats["avg"],
                "max_score": if_stats["max"],
                "precision": None, "recall": None, "f1": None,
            },
            "rf": {
                "name": "Random Forest",
                "type": "supervised",
                "index": "soc-rf-anomalies",
                "alerts": _count("soc-rf-anomalies"),
                "avg_score": rf_stats["avg"],
                "max_score": rf_stats["max"],
                "precision": round(rf_metrics.get("precision", 0), 3),
                "recall":    round(rf_metrics.get("recall", 0), 3),
                "f1":        round(rf_metrics.get("f1", 0), 3),
                "trained_at": rf_metrics.get("trained_at", ""),
            },
            "ensemble": {
                "alerts":  _count("soc-ensemble-anomalies"),
                "weights": {"IF": 0.30, "RF": 0.35, "DL": 0.20, "Rate": 0.15},
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents/<inc_id>/analysis")
def api_incident_analysis(inc_id):
    """Retourne l'analyse LLM d'un incident. Lance l'analyse si absente."""
    try:
        r = es.get(index="soc-incidents", id=inc_id)
        doc = r["_source"]
        analysis = doc.get("ai_analysis")

        if analysis:
            return jsonify({"status": "ready", "analysis": analysis})

        # Pas encore d'analyse — lancer en background et retourner pending
        def _run():
            try:
                result = analyze_incident(es, {
                    "src_ip":        doc.get("src_ip", ""),
                    "log_type":      doc.get("type", ""),
                    "anomaly_score": doc.get("unified_score", 0),
                    "severity":      doc.get("severity", "medium"),
                    "timestamp":     doc.get("created_at", ""),
                })
                if result:
                    es.update(index="soc-incidents", id=inc_id, body={
                        "doc": {"ai_analysis": result}
                    })
            except Exception as e:
                import logging; logging.getLogger("llm").error(f"on-demand LLM: {e}")

        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"status": "pending", "analysis": None})

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 404


# ─── HTML REPORT ─────────────────────────────────────────────────────────────

@app.route("/report/html")
def generate_html_report():
    return render_template("report.html")


@app.route("/pipeline")
@require_level("L2")
def pipeline_page():
    import subprocess
    def check_proc(pattern):
        try:
            r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
            return bool(r.stdout.strip())
        except:
            return False
    def check_port(port):
        try:
            import socket
            with socket.create_connection(("localhost", port), timeout=1):
                return True
        except:
            return False

    services = {
        "filebeat":    {"up": check_proc("filebeat"),     "port": None,  "role": "Collecte logs"},
        "logstash":    {"up": check_proc("logstash"),     "port": 5044,  "role": "Pipeline & enrichissement"},
        "elasticsearch":{"up": check_port(9200),          "port": 9200,  "role": "Stockage & indexation"},
        "kibana":      {"up": check_port(5601),           "port": 5601,  "role": "Visualisation"},
        "flask":       {"up": check_port(5000),           "port": 5000,  "role": "API & Dashboard"},
        "ia_if":       {"up": check_proc("ia_detector"),  "port": None,  "role": "Isolation Forest"},
        "ia_rf":       {"up": check_proc("rf_detector"),  "port": None,  "role": "Random Forest supervisé"},
        "ia_dl":       {"up": check_proc("dl_detector"),  "port": None,  "role": "Autoencoder DL"},
        "ia_rate":     {"up": check_proc("rate_detector"),"port": None,  "role": "Détecteur de volume"},
        "ia_ensemble": {"up": check_proc("ensemble_detector"),"port": None,"role": "Ensemble (vote 4 modèles)"},
        "ollama":      {"up": check_port(11434),          "port": 11434, "role": "LLM llama3 (analyse incidents)"},
    }
    return render_template("pipeline.html", services=services, current_user=get_current_user())


@app.route("/api/pipeline/status")
@require_level("L2")
def api_pipeline_status():
    import subprocess
    def check_proc(pattern):
        try:
            r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
            return bool(r.stdout.strip())
        except:
            return False
    def check_port(port):
        try:
            import socket
            with socket.create_connection(("localhost", port), timeout=1):
                return True
        except:
            return False
    from elasticsearch import Elasticsearch as _ES
    _es = _ES(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))

    def _count(idx):
        try: return _es.count(index=idx, query={"range": {"@timestamp": {"gte": "now-1m"}}})["count"]
        except: return 0

    return jsonify({
        "services": {
            "filebeat":      check_proc("filebeat"),
            "logstash":      check_proc("logstash"),
            "elasticsearch": check_port(9200),
            "kibana":        check_port(5601),
            "flask":         check_port(5000),
            "ia_if":         check_proc("ia_detector"),
            "ia_rf":         check_proc("rf_detector"),
            "ia_dl":         check_proc("dl_detector"),
            "ia_rate":       check_proc("rate_detector"),
            "ia_ensemble":   check_proc("ensemble_detector"),
            "ollama":        check_port(11434),
        },
        "throughput": {
            "logs_1min":     _count("soc-logs*"),
            "if_alerts_1min":_count("soc-anomalies"),
            "rf_alerts_1min":_count("soc-rf-anomalies"),
            "dl_alerts_1min":_count("soc-dl-anomalies"),
            "incidents_today": _es.count(index="soc-incidents", query={"range": {"created_at": {"gte": "now-24h"}}})["count"],
        }
    })


@app.route("/mesures")
@require_auth
def mesures_page():
    return render_template("mesures.html")


@app.route("/playbooks")
@require_auth
def playbooks_page():
    import markdown
    playbook_dir = os.path.join(os.path.dirname(__file__), "docs", "playbooks")
    playbooks = []
    for fname in sorted(os.listdir(playbook_dir)):
        if fname.endswith(".md"):
            with open(os.path.join(playbook_dir, fname)) as f:
                raw = f.read()
            html_content = markdown.markdown(raw, extensions=["tables", "fenced_code"])
            title = raw.split("\n")[0].lstrip("# ").strip()
            slug = fname.replace(".md", "")
            playbooks.append({"slug": slug, "title": title, "html": html_content, "fname": fname})
    return render_template("playbooks.html", playbooks=playbooks, current_user=get_current_user())


# ─── OLLAMA DESCRIPTION PAGE ──────────────────────────────────────────────────

OLLAMA_FEATURES = [
    {"name": "failed_ratio",           "desc": "Ratio échecs/total SSH par IP sur 5min",              "priority": "HIGH",   "priority_class": "sev-high",     "model": "RF + IF"},
    {"name": "unique_users_tried",      "desc": "Nombre d'usernames différents essayés",               "priority": "HIGH",   "priority_class": "sev-high",     "model": "RF + Ensemble"},
    {"name": "time_between_attempts",   "desc": "Délai moyen entre tentatives (ms) — détecte tools",  "priority": "HIGH",   "priority_class": "sev-high",     "model": "IF + DL"},
    {"name": "geo_country",             "desc": "Pays d'origine GeoIP — signaux de contexte",          "priority": "MEDIUM", "priority_class": "sev-medium",   "model": "RF"},
    {"name": "is_known_scanner",        "desc": "IP dans listes Shodan/AbuseIPDB connues",             "priority": "HIGH",   "priority_class": "sev-high",     "model": "RF + Rate"},
    {"name": "port_scan_score",         "desc": "Nombre de ports distincts scannés en 10min",          "priority": "MEDIUM", "priority_class": "sev-medium",   "model": "IF"},
    {"name": "payload_length_avg",      "desc": "Longueur moyenne des requêtes HTTP (SQLi détection)", "priority": "HIGH",   "priority_class": "sev-high",     "model": "RF + DL"},
    {"name": "is_known_exploit_path",   "desc": "URL correspond à chemin d'exploit connu (CVE)",       "priority": "CRITICAL","priority_class": "sev-critical", "model": "RF"},
    {"name": "hour_sliding_rate",       "desc": "Taux de logs sur 1h glissante (vs 24h baseline)",     "priority": "MEDIUM", "priority_class": "sev-medium",   "model": "IF + Rate"},
    {"name": "ssh_accepted_after_fails","desc": "Auth réussie après X échecs — credential stuffing",   "priority": "CRITICAL","priority_class": "sev-critical", "model": "RF + Ensemble"},
    {"name": "multi_service_attacker",  "desc": "IP qui attaque SSH + HTTP simultanément",             "priority": "HIGH",   "priority_class": "sev-high",     "model": "Ensemble"},
    {"name": "response_code_dist",      "desc": "Distribution 4xx/5xx HTTP — indicateur scan/bruteforce","priority": "MEDIUM","priority_class": "sev-medium",  "model": "RF + DL"},
]

@app.route("/ollama")
@require_level("L2")
def ollama_page():
    return render_template("ollama.html", features=OLLAMA_FEATURES, current_user=get_current_user())


@app.route("/kibana")
@require_level("L2")
def kibana_page():
    kibana_base = "http://192.168.50.10:5601"
    indices = [
        {
            "id":          "28413f52-d6ec-418b-ad9b-c465d1371716",
            "title":       "soc-logs*",
            "description": "Logs Filebeat/Logstash : auth SSH, HTTP, syslog. Champ timestamp : @timestamp",
            "fields":      ["@timestamp","log_type","src_ip","ssh_user","tags","message","severity","hostname","program"],
            "color":       "blue",
            "icon":        "fa-database",
            "count_index": "soc-logs*",
        },
        {
            "id":          "soc-incidents-001",
            "title":       "soc-incidents",
            "description": "Incidents SOC : verdict LLM, scores ML, statut analyste, auto-labels IA",
            "fields":      ["created_at","severity","status","verdict","src_ip","anomaly_score","if_score","rf_score","dl_score","llm_verdict","llm_confidence","auto_labeled"],
            "color":       "red",
            "icon":        "fa-ticket-alt",
            "count_index": "soc-incidents",
        },
        {
            "id":          "db0d7754-417d-4fec-86d5-993cfd1c930a",
            "title":       "soc-anomalies",
            "description": "Anomalies Isolation Forest : anomaly_score, src_ip, alert_type",
            "fields":      ["@timestamp","anomaly_score","src_ip","alert_type","severity","ssh_user","log_type"],
            "color":       "purple",
            "icon":        "fa-brain",
            "count_index": "soc-anomalies",
        },
        {
            "id":          "soc-rf-anomalies-001",
            "title":       "soc-rf-anomalies",
            "description": "Anomalies Random Forest : rf_score, features SF SSH",
            "fields":      ["@timestamp","rf_score","src_ip","severity","log_type","ssh_user"],
            "color":       "green",
            "icon":        "fa-tree",
            "count_index": "soc-rf-anomalies",
        },
        {
            "id":          "soc-dl-anomalies-001",
            "title":       "soc-dl-anomalies",
            "description": "Anomalies Autoencoder DL : reconstruction_loss, anomaly_score",
            "fields":      ["@timestamp","anomaly_score","reconstruction_loss","threshold","src_ip","severity","log_type"],
            "color":       "orange",
            "icon":        "fa-project-diagram",
            "count_index": "soc-dl-anomalies",
        },
        {
            "id":          "soc-ensemble-anomalies-001",
            "title":       "soc-ensemble-anomalies",
            "description": "Score Ensemble (IF×0.30 + RF×0.35 + DL×0.20 + Rate×0.15), votes par modèle",
            "fields":      ["@timestamp","ensemble_score","if_score","rf_score","dl_score","rate_score","votes","src_ip","severity"],
            "color":       "yellow",
            "icon":        "fa-layer-group",
            "count_index": "soc-ensemble-anomalies",
        },
        {
            "id":          "cve-dv-0001-0001-0001-000000000001",
            "title":       "soc-cve-alerts",
            "description": "Alertes CVE NVD : cve_id, cvss_score, description vulnérabilité",
            "fields":      ["@timestamp","cve_id","cvss_score","severity","description"],
            "color":       "orange",
            "icon":        "fa-bug",
            "count_index": "soc-cve-alerts",
        },
    ]
    # Fetch doc counts
    for idx in indices:
        try:
            idx["doc_count"] = es.count(index=idx["count_index"])["count"]
        except Exception:
            idx["doc_count"] = 0

    return render_template("kibana.html",
        current_user=get_current_user(),
        kibana_base=kibana_base,
        indices=indices,
    )


@app.route("/kibana-sso")
@require_level("L2")
def kibana_sso():
    """Auto-login Flask → Kibana : récupère le cookie de session Kibana et redirige."""
    kibana_host = "http://localhost:5601"
    target      = request.args.get("next", "http://192.168.50.10:5601/app/dashboards")
    try:
        resp = _requests.post(
            f"{kibana_host}/internal/security/login",
            json={
                "providerType": "basic",
                "providerName": "basic",
                "currentURL":   f"{kibana_host}/",
                "params":       {"username": ES_USER, "password": ES_PASSWORD},
            },
            headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
            timeout=5,
            allow_redirects=False,
        )
        r = make_response(redirect(target))
        # Forward Kibana session cookies — domain=192.168.50.10 covers both ports 5000 and 5601
        for name, value in resp.cookies.items():
            r.set_cookie(name, value, domain="192.168.50.10", path="/",
                         samesite="Lax", httponly=True)
        audit_log("kibana_sso", username=session.get("username"),
                  details={"target": target, "kibana_status": resp.status_code})
        return r
    except Exception as e:
        # Fallback: redirect directly (user will see Kibana login)
        return redirect(target)


@app.route("/api/kibana/status")
@require_level("L2")
def api_kibana_status():
    """Vérifie si Kibana est accessible et retourne la version."""
    try:
        r = _requests.get("http://localhost:5601/api/status",
                          auth=(ES_USER, ES_PASSWORD), timeout=3)
        d = r.json()
        return jsonify({
            "up":      True,
            "version": d.get("version", {}).get("number", "?"),
            "status":  d.get("status", {}).get("overall", {}).get("level", "?"),
        })
    except Exception as e:
        return jsonify({"up": False, "error": str(e)})


@app.route("/api/ollama/stats")
@require_level("L2")
def api_ollama_stats():
    try:
        total = es.count(index="soc-incidents")["count"]
        tp    = es.count(index="soc-incidents", query={"bool": {"should": [
            {"term": {"llm_verdict.keyword": "true_positive"}},
            {"term": {"ai_analysis.verdict.keyword": "true_positive"}},
        ]}})["count"]
        fp    = es.count(index="soc-incidents", query={"bool": {"should": [
            {"term": {"llm_verdict.keyword": "false_positive"}},
            {"term": {"ai_analysis.verdict.keyword": "false_positive"}},
        ]}})["count"]
        fb    = es.count(index="soc-incidents", query={"bool": {"should": [
            {"term": {"llm_model.keyword": "fallback"}},
            {"term": {"ai_analysis.model.keyword": "fallback"}},
        ]}})["count"]
        llm_analyzed = es.count(index="soc-incidents", query={"bool": {"should": [
            {"exists": {"field": "llm_verdict"}},
            {"exists": {"field": "ai_analysis.verdict"}},
        ]}})["count"]

        # Mémoire few-shot Ollama
        mem_path = os.path.join(os.path.dirname(__file__), "llm_memory.json")
        try:
            with open(mem_path) as f:
                memory = json.load(f)
            mem_count = len(memory)
            mem_tp = sum(1 for e in memory if e.get("verdict") == "true_positive")
            mem_fp = sum(1 for e in memory if e.get("verdict") == "false_positive")
        except Exception:
            mem_count, mem_tp, mem_fp = 0, 0, 0

        # Auto-labeler stats
        al_stats = {"total_auto_labeled": 0, "retrains_triggered": 0}
        try:
            al_path = os.path.join(os.path.dirname(__file__), "auto_labeler_stats.json")
            with open(al_path) as f:
                al_stats = json.load(f)
        except Exception:
            pass

        return jsonify({
            "analyzed":            llm_analyzed,
            "true_positive":       tp,
            "false_positive":      fp,
            "fallback":            fb,
            "labels_available":    tp + fp,
            "total":               total,
            "memory_examples":     mem_count,
            "memory_tp":           mem_tp,
            "memory_fp":           mem_fp,
            "auto_labeled":        al_stats.get("total_auto_labeled", 0),
            "auto_retrains":       al_stats.get("retrains_triggered", 0),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ollama/history")
@require_level("L2")
def api_ollama_history():
    try:
        r = es.search(
            index="soc-incidents",
            size=20,
            query={"exists": {"field": "llm_verdict"}},
            _source=["src_ip", "severity", "llm_verdict", "llm_attack_type",
                     "llm_confidence", "llm_summary", "llm_actions", "llm_model",
                     "created_at"],
        )
        out = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            out.append({
                "src_ip":        s.get("src_ip", ""),
                "severity":      s.get("severity", ""),
                "llm_verdict":   s.get("llm_verdict", ""),
                "llm_attack_type": s.get("llm_attack_type", ""),
                "llm_confidence": s.get("llm_confidence"),
                "llm_summary":   s.get("llm_summary", ""),
                "llm_actions":   s.get("llm_actions") or s.get("llm_recommended_actions") or [],
                "llm_model":     s.get("llm_model", ""),
                "created_at":    s.get("created_at", ""),
            })
        return jsonify(out)
    except Exception as e:
        return jsonify([])


@app.route("/api/ollama/export_labels")
@require_level("L2")
def api_ollama_export_labels():
    import csv, io
    try:
        r = es.search(
            index="soc-incidents",
            size=1000,
            query={"bool": {"must": [
                {"exists": {"field": "llm_verdict"}},
                {"terms": {"llm_verdict.keyword": ["true_positive", "false_positive"]}}
            ]}},
            _source=["src_ip", "severity", "llm_verdict", "llm_attack_type",
                     "llm_confidence", "anomaly_score", "created_at", "llm_model"],
        )
        rows = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            rows.append({
                "src_ip":        s.get("src_ip", ""),
                "severity":      s.get("severity", ""),
                "label":         1 if s.get("llm_verdict") == "true_positive" else 0,
                "llm_verdict":   s.get("llm_verdict", ""),
                "llm_attack_type": s.get("llm_attack_type", ""),
                "llm_confidence":  s.get("llm_confidence", ""),
                "anomaly_score": s.get("anomaly_score", ""),
                "created_at":    s.get("created_at", ""),
                "llm_model":     s.get("llm_model", ""),
            })
        path = os.path.join(os.path.dirname(__file__), "llm_labels.csv")
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else [])
            writer.writeheader()
            writer.writerows(rows)
        return jsonify({"count": len(rows), "path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ollama/retrain_rf", methods=["POST"])
@require_level("L3")
def api_ollama_retrain_rf():
    try:
        import subprocess
        result = subprocess.run(
            ["/home/arthur-leywin/mini-soc/venv/bin/python3",
             "/home/arthur-leywin/mini-soc/rf_detector.py", "--train-only"],
            capture_output=True, text=True, timeout=120
        )
        lines = result.stdout.strip().split("\n")
        info = {}
        for line in lines:
            if "F1" in line or "f1" in line:      info["f1"] = line.strip()
            if "Precision" in line:               info["precision"] = line.strip()
            if "Recall" in line:                  info["recall"] = line.strip()
            if "Total" in line or "logs" in line: info["dataset_size"] = line.strip()
        info["llm_labels"] = "—"
        info["stdout"] = result.stdout[-1000:]
        return jsonify(info)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout (>120s)"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ollama/test", methods=["POST"])
@require_level("L2")
def api_ollama_test():
    try:
        from llm_analyzer import analyze_incident
        test_incident = {
            "src_ip": "192.168.122.231",
            "severity": "critical",
            "anomaly_score": 0.98,
            "log_type": "auth",
            "ssh_user": "root",
            "description": "Test LLM — SSH brute force depuis 192.168.122.231 | 234 tentatives | IF=0.9 RF=0.98 DL=0.7 Rate=166",
        }
        result = analyze_incident(test_incident)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ollama/auto_label_stats")
@require_level("L2")
def api_auto_label_stats():
    stats_path = os.path.join(os.path.dirname(__file__), "auto_labeler_stats.json")
    try:
        with open(stats_path) as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({
            "total_auto_labeled": 0, "true_positives": 0,
            "false_positives": 0, "retrains_triggered": 0,
            "last_run": None, "history": [],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ollama/run_auto_label", methods=["POST"])
@require_level("L2")
def api_run_auto_label():
    """Déclenche manuellement un cycle d'auto-étiquetage."""
    try:
        import subprocess
        result = subprocess.run(
            ["/home/arthur-leywin/mini-soc/venv/bin/python3",
             "/home/arthur-leywin/mini-soc/auto_labeler.py", "--once"],
            capture_output=True, text=True, timeout=30,
            cwd="/home/arthur-leywin/mini-soc",
        )
        output = (result.stdout + result.stderr).strip()
        return jsonify({"status": "ok", "output": output, "returncode": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout (>30s)"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── ADMIN USERS ─────────────────────────────────────────────────────────────

@app.route("/admin/users")
@require_level("L3")
def admin_users_page():
    users = _load_users()
    user_list = [{"username": k, **v} for k, v in users.items()]
    return render_template("admin_users.html", users=user_list, current_user=get_current_user())


@app.route("/admin/users/new", methods=["POST"])
@require_level("L3")
def admin_create_user():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "").strip()
    name     = request.form.get("name", "").strip()
    level    = request.form.get("level", "L1")
    email    = request.form.get("email", "").strip()
    users = _load_users()
    if not username or not password or username in users:
        return redirect(url_for("admin_users_page"))
    users[username] = {
        "password": _hash(password),
        "name": name or username,
        "level": level,
        "role": "analyst" if level == "L1" else "senior" if level == "L2" else "admin",
        "email": email,
        "active": True,
    }
    _save_users(users)
    return redirect(url_for("admin_users_page"))


def _reassign_from(deactivated_name):
    """
    Réassigne tous les incidents ouverts d'un utilisateur désactivé
    vers l'analyste actif le moins chargé du même niveau.
    """
    try:
        r = es.search(index="soc-incidents", size=200,
            query={"term": {"assigned_to.keyword": deactivated_name}},
            _source=["severity", "assigned_to", "level"]
        )
        hits = r["hits"]["hits"]
        if not hits:
            return 0
        reassigned = 0
        for h in hits:
            sev  = h["_source"].get("severity", "medium")
            new_name, new_level = auto_assign(sev)
            if new_name and new_name != deactivated_name:
                es.update(index="soc-incidents", id=h["_id"], body={"doc": {
                    "assigned_to": new_name,
                    "level":       new_level,
                    "updated_at":  datetime.utcnow().isoformat() + "Z",
                }})
                reassigned += 1
        log.info(f"Réassignation : {reassigned} incidents de {deactivated_name}")
        return reassigned
    except Exception as e:
        log.error(f"Reassign error: {e}")
        return 0


@app.route("/admin/users/<username>/toggle", methods=["POST"])
@require_level("L3")
def admin_toggle_user(username):
    users = _load_users()
    if username in users and username != session.get("username"):
        currently_active = users[username].get("active", True)
        users[username]["active"] = not currently_active
        _save_users(users)
        # Si on désactive → réassigner ses incidents ouverts
        if currently_active:
            deactivated_name = users[username]["name"]
            threading.Thread(target=_reassign_from, args=(deactivated_name,), daemon=True).start()
        audit_log("user_toggle", details={"target": username,
                  "new_state": "active" if not currently_active else "inactive"})
    return redirect(url_for("admin_users_page"))


@app.route("/admin/users/<username>/reset_password", methods=["POST"])
@require_level("L3")
def admin_reset_password(username):
    new_pw = request.form.get("password", "").strip()
    users = _load_users()
    if username in users and new_pw:
        users[username]["password"] = _hash(new_pw)
        _save_users(users)
    return redirect(url_for("admin_users_page"))


@app.route("/api/admin/reassign_inactive", methods=["POST"])
@require_level("L3")
def api_reassign_inactive():
    """Réassigne tous les incidents ouverts des utilisateurs désactivés."""
    users = _load_users()
    inactive_names = [u["name"] for u in users.values()
                      if not u.get("active", True) and u.get("name")]
    total = 0
    details = {}
    for name in inactive_names:
        n = _reassign_from(name)
        if n > 0:
            details[name] = n
            total += n
    audit_log("bulk_reassign_inactive", details={"reassigned": total, "from": list(details.keys())})
    return jsonify({"ok": True, "total_reassigned": total, "details": details})


@app.route("/admin/users/<username>/update_email", methods=["POST"])
@require_level("L3")
def admin_update_email(username):
    email = request.form.get("email", "").strip()
    users = _load_users()
    if username in users:
        users[username]["email"] = email
        _save_users(users)
        audit_log("admin_email_update", details={"target": username, "email": email})
    return redirect(url_for("admin_users_page"))


@app.route("/admin/users/<username>/update", methods=["POST"])
@require_level("L3")
def admin_update_user(username):
    current = get_current_user()
    name  = request.form.get("name", "").strip()
    level = request.form.get("level", "").strip()
    email = request.form.get("email", "").strip()
    users = _load_users()
    if username not in users:
        return redirect(url_for("admin_users_page"))
    if name:
        users[username]["name"] = name
    if level in ("L1", "L2", "L3"):
        if not (username == current["username"] and level != "L3"):
            users[username]["level"] = level
            users[username]["role"] = "analyst" if level == "L1" else "senior" if level == "L2" else "admin"
    users[username]["email"] = email
    _save_users(users)
    audit_log("admin_update_user", details={"target": username, "name": name, "level": level})
    return redirect(url_for("admin_users_page"))


@app.route("/admin/users/<username>/delete", methods=["POST"])
@require_level("L3")
def admin_delete_user(username):
    current = get_current_user()
    if username == current["username"]:
        return jsonify({"error": "Impossible de supprimer votre propre compte"}), 400
    users = _load_users()
    if username not in users:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    deleted_name = users[username].get("name", username)
    del users[username]
    _save_users(users)
    audit_log("admin_delete_user", details={"target": username, "name": deleted_name})
    return jsonify({"status": "ok", "deleted": username})


@app.route("/profile")
@require_auth
def profile_page():
    return render_template("profile.html", current_user=get_current_user())


@app.route("/profile/change_password", methods=["POST"])
@require_auth
def change_password():
    user = get_current_user()
    old_pw  = request.form.get("old_password", "")
    new_pw  = request.form.get("new_password", "").strip()
    users   = _load_users()
    u       = users.get(user["username"])
    if not u or not _check_password(old_pw, u["password"]) or len(new_pw) < 4:
        return render_template("profile.html", current_user=user,
                               error="Ancien mot de passe incorrect ou nouveau trop court.")
    users[user["username"]]["password"] = _hash(new_pw)
    audit_log("password_change", details={"username": user["username"]})
    _save_users(users)
    return render_template("profile.html", current_user=user, success="Mot de passe mis à jour.")


@app.route("/profile/update_email", methods=["POST"])
@require_auth
def update_email():
    user  = get_current_user()
    email = request.form.get("email", "").strip()
    users = _load_users()
    u     = users.get(user["username"])
    if u and email:
        users[user["username"]]["email"] = email
        _save_users(users)
        audit_log("email_update", details={"email": email})
    return redirect(url_for("profile_page"))


@app.route("/profile/setup_totp")
@require_auth
def setup_totp():
    user = get_current_user()
    users = _load_users()
    u = users.get(user["username"])
    # Generate a new secret only if none exists
    secret = u.get("totp_secret") or pyotp.random_base32()
    if not u.get("totp_secret"):
        users[user["username"]]["totp_secret"] = secret
        _save_users(users)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user["username"], issuer_name="MiniSOC")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template("profile.html", current_user=user,
                           totp_secret=secret, totp_qr=qr_b64)


@app.route("/profile/disable_totp", methods=["POST"])
@require_auth
def disable_totp():
    user = get_current_user()
    users = _load_users()
    users[user["username"]].pop("totp_secret", None)
    _save_users(users)
    audit_log("totp_disabled", details={"username": user["username"]})
    return render_template("profile.html", current_user=get_current_user(),
                           success="Authentification MFA désactivée.")


@app.route("/profile/verify_totp", methods=["POST"])
@require_auth
def verify_totp():
    user = get_current_user()
    users = _load_users()
    u = users.get(user["username"])
    code = request.form.get("totp_code", "").strip()
    secret = u.get("totp_secret", "")
    if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
        audit_log("totp_verified", details={"username": user["username"]})
        return render_template("profile.html", current_user=user,
                               totp_secret=secret,
                               success="✅ Code valide — MFA activé et opérationnel.")
    return render_template("profile.html", current_user=user,
                           totp_secret=secret,
                           error="Code invalide. Vérifier l'heure ou re-scanner le QR code.")


@app.route("/admin/audit")
@require_level("L3")
def audit_log_page():
    try:
        result = es.search(index="soc-audit-log", query={"match_all": {}},
                           sort=[{"@timestamp": {"order": "desc"}}], size=200)
        events = [{"id": h["_id"], **h["_source"]} for h in result["hits"]["hits"]]
    except Exception:
        events = []
    return render_template("audit_log.html", events=events, current_user=get_current_user())


@app.route("/api/current_user")
def api_current_user():
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "username": user["username"],
                    "name": user["name"], "level": user["level"]})


@app.route("/api/mesures")
def api_mesures():
    """Analyse les incidents/anomalies actifs et retourne des mesures de remédiation contextuelles."""
    REMEDIATION = {
        "ssh_brute_force": {
            "title": "Brute Force SSH",
            "icon": "fa-terminal",
            "color": "var(--red)",
            "priority": "critique",
            "measures": [
                "Bloquer l'IP attaquante via iptables : iptables -A INPUT -s <IP> -j DROP",
                "Installer et configurer fail2ban : apt install fail2ban (bannissement auto après 5 échecs)",
                "Désactiver l'authentification par mot de passe SSH : PasswordAuthentication no dans /etc/ssh/sshd_config",
                "Utiliser uniquement des clés SSH pour l'authentification",
                "Changer le port SSH par défaut (22 → port non standard) : Port 2222",
                "Limiter les utilisateurs SSH autorisés : AllowUsers arthur",
                "Activer l'authentification à deux facteurs (2FA) sur SSH",
                "Restreindre l'accès SSH aux IPs autorisées via AllowFrom ou firewall",
            ],
            "commands": [
                "sudo iptables -A INPUT -s {src_ip} -j DROP",
                "sudo apt install fail2ban -y && sudo systemctl enable fail2ban",
                "sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
                "sudo systemctl restart sshd",
            ]
        },
        "web_scan": {
            "title": "Scan Web / Reconnaissance",
            "icon": "fa-spider",
            "color": "var(--orange)",
            "priority": "haute",
            "measures": [
                "Bloquer l'IP du scanner via WAF ou iptables",
                "Activer mod_evasive sur Apache pour limiter les requêtes par IP",
                "Configurer mod_security (WAF) : apt install libapache2-mod-security2",
                "Masquer la version d'Apache : ServerTokens Prod et ServerSignature Off",
                "Désactiver le listing des répertoires : Options -Indexes",
                "Retirer les fichiers sensibles accessibles (/.env, /.git, /admin)",
                "Mettre en place un honeypot pour détecter les scanners",
            ],
            "commands": [
                "sudo apt install libapache2-mod-evasive libapache2-mod-security2 -y",
                "sudo a2enmod evasive security2",
                "echo 'ServerTokens Prod' >> /etc/apache2/apache2.conf",
                "echo 'ServerSignature Off' >> /etc/apache2/apache2.conf",
            ]
        },
        "http_flood": {
            "title": "HTTP Flood / DDoS",
            "icon": "fa-tachometer-alt",
            "color": "var(--orange)",
            "priority": "haute",
            "measures": [
                "Activer le rate limiting dans Apache avec mod_ratelimit",
                "Configurer iptables pour limiter les connexions par IP : --limit 25/min",
                "Mettre en place un reverse proxy (nginx) avec limite de requêtes",
                "Utiliser un CDN ou service anti-DDoS (Cloudflare)",
                "Bloquer les User-Agents suspects (bots, scanners)",
                "Configurer des connexions max par IP dans Apache : MaxConnPerIP",
            ],
            "commands": [
                "sudo iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j REJECT",
                "sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/min --limit-burst 100 -j ACCEPT",
                "sudo a2enmod ratelimit",
            ]
        },
        "lfi": {
            "title": "Local File Inclusion (LFI)",
            "icon": "fa-file-code",
            "color": "var(--red)",
            "priority": "critique",
            "measures": [
                "Valider et filtrer tous les paramètres d'inclusion dans le code PHP/Python",
                "Désactiver allow_url_include dans php.ini",
                "Mettre en place un WAF (mod_security) avec règles OWASP CRS",
                "Utiliser un chroot ou conteneur pour limiter l'accès au filesystem",
                "Auditer tout le code source pour les inclusions de fichiers dynamiques",
                "Appliquer le principe du moindre privilège au serveur web (www-data)",
            ],
            "commands": [
                "sudo apt install libapache2-mod-security2 -y",
                "sudo a2enmod security2",
                "sudo ln -s /usr/share/modsecurity-crs /etc/modsecurity/crs",
            ]
        },
        "sqli": {
            "title": "Injection SQL",
            "icon": "fa-database",
            "color": "var(--red)",
            "priority": "critique",
            "measures": [
                "Utiliser des requêtes préparées (prepared statements) dans tout le code",
                "Mettre en place un WAF avec règles anti-SQLi (mod_security + OWASP CRS)",
                "Limiter les permissions de la base de données (pas de DROP, pas de SELECT *)",
                "Activer le logging des requêtes SQL pour détecter les tentatives",
                "Scanner le code source avec sqlmap en mode audit pour trouver les vulnérabilités",
                "Valider et sanitiser toutes les entrées utilisateur côté serveur",
            ],
            "commands": [
                "sudo apt install libapache2-mod-security2 -y",
                "# Audit: sqlmap -u 'http://target/page?id=1' --level=5 --risk=3 --batch",
            ]
        },
        "xss": {
            "title": "Cross-Site Scripting (XSS)",
            "icon": "fa-code",
            "color": "var(--yellow)",
            "priority": "haute",
            "measures": [
                "Ajouter les headers de sécurité HTTP : Content-Security-Policy, X-XSS-Protection",
                "Encoder toutes les sorties HTML (htmlspecialchars en PHP)",
                "Valider et sanitiser les entrées utilisateur (whitelist, pas blacklist)",
                "Activer HTTPOnly et Secure sur les cookies de session",
                "Implémenter une CSP stricte pour bloquer les scripts inline",
            ],
            "commands": [
                "# Dans Apache config:",
                "Header always set X-XSS-Protection '1; mode=block'",
                "Header always set Content-Security-Policy \"default-src 'self'\"",
                "Header always set X-Content-Type-Options 'nosniff'",
            ]
        },
        "post_exploitation": {
            "title": "Post-Exploitation / Accès Interne",
            "icon": "fa-user-secret",
            "color": "var(--red)",
            "priority": "critique",
            "measures": [
                "ISOLER IMMÉDIATEMENT la machine compromise du réseau",
                "Changer TOUS les mots de passe (système, services, BDD) depuis une machine saine",
                "Révoquer et régénérer toutes les clés SSH",
                "Analyser les connexions SSH récentes : last -n 50 et who",
                "Vérifier les crontabs et services pour backdoors : crontab -l, systemctl list-units",
                "Auditer les fichiers modifiés récemment : find / -newer /tmp/ref -mtime -1 -type f",
                "Analyser les logs auth.log pour identifier les commandes exécutées",
                "Installer auditd pour le suivi des syscalls post-incident",
                "Envisager une reinstallation complète si le système est compromis",
            ],
            "commands": [
                "last -n 50 | grep -v 'still logged'",
                "sudo find / -newer /etc/passwd -mtime -1 -type f 2>/dev/null | grep -v proc",
                "sudo apt install auditd -y && sudo auditctl -e 1",
                "sudo grep 'session opened' /var/log/auth.log | tail -20",
            ]
        },
        "nmap_scan": {
            "title": "Scan de Ports (Nmap)",
            "icon": "fa-network-wired",
            "color": "var(--yellow)",
            "priority": "moyenne",
            "measures": [
                "Activer le firewall et fermer les ports inutilisés",
                "Configurer iptables ou ufw pour n'exposer que les ports nécessaires",
                "Utiliser un IDS (Suricata) pour détecter les scans Nmap",
                "Masquer les bannières de services (ServerTokens, SSH banner)",
                "Mettre en place un système de détection de scans (psad, portsentry)",
                "Auditer régulièrement les ports ouverts : nmap -sV localhost",
            ],
            "commands": [
                "sudo ufw enable && sudo ufw default deny incoming",
                "sudo ufw allow 22/tcp && sudo ufw allow 80/tcp",
                "sudo apt install psad -y",
                "sudo nmap -sV localhost",
            ]
        },
        "brute_force": {
            "title": "Brute Force (général)",
            "icon": "fa-lock",
            "color": "var(--red)",
            "priority": "critique",
            "measures": [
                "Mettre en place fail2ban pour tous les services exposés",
                "Utiliser des mots de passe forts (min. 16 caractères, complexes)",
                "Activer la 2FA sur tous les accès distants",
                "Limiter les tentatives de connexion via account lockout policy",
            ],
            "commands": [
                "sudo apt install fail2ban -y",
                "sudo systemctl enable --now fail2ban",
            ]
        },
        "anomaly_ia": {
            "title": "Anomalie IA (comportement suspect)",
            "icon": "fa-brain",
            "color": "var(--purple)",
            "priority": "haute",
            "measures": [
                "Analyser les logs complets de l'IP signalée",
                "Corréler avec les autres sources de logs (apache, syslog)",
                "Vérifier si l'IP est dans des listes noires connues (VirusTotal, AbuseIPDB)",
                "Investiguer manuellement les connexions récentes depuis cette IP",
                "Bloquer l'IP préventivement si le score est >= 0.7",
            ],
            "commands": [
                "# Vérifier IP dans AbuseIPDB:",
                "curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode 'ipAddress={src_ip}' -H 'Key: YOUR_API_KEY'",
            ]
        },
        "cve": {
            "title": "Vulnérabilité CVE",
            "icon": "fa-bug",
            "color": "var(--yellow)",
            "priority": "haute",
            "measures": [
                "Appliquer les patches de sécurité : apt update && apt upgrade",
                "Vérifier la version du logiciel affecté et mettre à jour",
                "Si pas de patch disponible, appliquer des mesures compensatoires (WAF, désactivation du service)",
                "Scanner régulièrement les CVEs avec OpenVAS ou Nessus",
                "Mettre en place un processus de gestion des vulnérabilités",
            ],
            "commands": [
                "sudo apt update && sudo apt upgrade -y",
                "sudo apt install unattended-upgrades -y",
                "sudo dpkg-reconfigure -plow unattended-upgrades",
            ]
        },
        "ids_alert": {
            "title": "Alerte IDS",
            "icon": "fa-exclamation-triangle",
            "color": "var(--orange)",
            "priority": "haute",
            "measures": [
                "Analyser la signature IDS déclenchée pour confirmer ou infirmer",
                "Vérifier les logs associés à l'IP source",
                "Mettre à jour les règles Suricata/Snort si faux positif confirmé",
                "Créer un incident si l'alerte est confirmée comme vraie positive",
            ],
            "commands": [
                "sudo suricata-update && sudo systemctl restart suricata",
            ]
        },
    }

    # Récupérer les incidents actifs depuis ES
    active_attacks = {}
    try:
        r = es.search(
            index="soc-incidents",
            size=50,
            query={"bool": {"must": [
                {"range": {"created_at": {"gte": "now-24h"}}},
                {"terms": {"status": ["awaiting_action", "in_progress"]}}
            ]}},
            sort=[{"created_at": {"order": "desc"}}]
        )
        for h in r["hits"]["hits"]:
            inc = h["_source"]
            itype = inc.get("type", "anomaly_ia")
            src_ip = inc.get("src_ip", "")
            severity = inc.get("severity", "medium")
            score = inc.get("unified_score", inc.get("anomaly_score", 0))

            if itype not in active_attacks:
                active_attacks[itype] = {
                    "count": 0, "ips": set(), "max_score": 0,
                    "severity": severity, "last_seen": inc.get("created_at", "")
                }
            active_attacks[itype]["count"] += 1
            if src_ip:
                active_attacks[itype]["ips"].add(src_ip)
            active_attacks[itype]["max_score"] = max(active_attacks[itype]["max_score"], score)
    except Exception as e:
        pass

    # Détecter post-exploitation : connexion SSH réussie depuis une IP qui a fait du brute force
    post_exploit_detected = False
    try:
        # Chercher des connexions "Accepted password" dans les logs auth récents
        r2 = es.search(
            index="soc-logs*", size=10,
            query={"bool": {"must": [
                {"term": {"log_type": "auth"}},
                {"range": {"@timestamp": {"gte": "now-24h"}}},
                {"match": {"message": "Accepted password"}}
            ]}},
            sort=[{"@timestamp": {"order": "desc"}}]
        )
        if r2["hits"]["total"]["value"] > 0:
            post_exploit_detected = True
            if "post_exploitation" not in active_attacks:
                active_attacks["post_exploitation"] = {
                    "count": r2["hits"]["total"]["value"],
                    "ips": {h["_source"].get("src_ip", "") for h in r2["hits"]["hits"] if h["_source"].get("src_ip")},
                    "max_score": 1.0,
                    "severity": "critical",
                    "last_seen": r2["hits"]["hits"][0]["_source"].get("@timestamp", "")
                }
    except Exception:
        pass

    # Construire la réponse
    result = []
    for itype, info in active_attacks.items():
        rem = REMEDIATION.get(itype, REMEDIATION.get("anomaly_ia"))
        ips_list = sorted(list(info["ips"]))
        commands = [
            c.replace("{src_ip}", ips_list[0] if ips_list else "X.X.X.X")
            for c in rem.get("commands", [])
        ]
        result.append({
            "type":       itype,
            "title":      rem["title"],
            "icon":       rem["icon"],
            "color":      rem["color"],
            "priority":   rem["priority"],
            "count":      info["count"],
            "ips":        ips_list[:5],
            "max_score":  round(info["max_score"], 2),
            "severity":   info["severity"],
            "last_seen":  info["last_seen"],
            "measures":   rem["measures"],
            "commands":   commands,
        })

    # Trier par priorité : critique > haute > moyenne
    prio_order = {"critique": 0, "haute": 1, "moyenne": 2}
    result.sort(key=lambda x: (prio_order.get(x["priority"], 3), -x["max_score"]))

    # Stats globales
    total_critical = sum(1 for r in result if r["priority"] == "critique")
    total_high     = sum(1 for r in result if r["priority"] == "haute")

    return jsonify({
        "attacks":        result,
        "total_types":    len(result),
        "total_critical": total_critical,
        "total_high":     total_high,
        "post_exploit":   post_exploit_detected,
        "generated_at":   datetime.now(timezone.utc).isoformat()
    })


# ─── INCIDENT DETAIL + DELEGATION ───────────────────────────────────────────

@app.route("/incidents/<inc_id>")
@require_auth
def incident_detail(inc_id):
    user = get_current_user()
    try:
        r = es.get(index="soc-incidents", id=inc_id)
        inc = {"id": r["_id"], **r["_source"]}
    except Exception:
        return render_template("404.html"), 404

    # L1 can only see assigned incidents
    if user and LEVEL_ORDER.get(user["level"], 0) < LEVEL_ORDER["L2"]:
        if inc.get("assigned_to") not in ("", "None", None, user.get("name")):
            return render_template("403.html", user=user), 403

    src_ip = inc.get("src_ip", "")

    # Related logs from same IP (last 24h)
    related_logs = []
    if src_ip:
        try:
            r2 = es.search(
                index="soc-logs*",
                query={"bool": {"must": [
                    {"term": {"src_ip": src_ip}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]}},
                sort=[{"@timestamp": {"order": "desc"}}],
                size=20
            )
            related_logs = [{"_id": h["_id"], "_index": h["_index"], **h["_source"]} for h in r2["hits"]["hits"]]
        except Exception:
            pass

    # Related incidents from same IP
    related_incidents = []
    if src_ip:
        try:
            r3 = es.search(
                index="soc-incidents",
                query={"bool": {"must": [{"term": {"src_ip": src_ip}}],
                                "must_not": [{"ids": {"values": [inc_id]}}]}},
                sort=[{"created_at": {"order": "desc"}}],
                size=10
            )
            related_incidents = [{"id": h["_id"], **h["_source"]} for h in r3["hits"]["hits"]]
        except Exception:
            pass

    # List of users for L3 delegation
    analysts = []
    if user and user.get("level") == "L3":
        all_users = _load_users()
        analysts = sorted([
            {"username": u, **d}
            for u, d in all_users.items()
            if d.get("active", True) and u != "admin"
        ], key=lambda x: x.get("level", "L1"))

    return render_template("incident_detail.html",
        inc=inc, related_logs=related_logs, related_incidents=related_incidents,
        analysts=analysts, current_user=user)


@app.route("/incidents/<inc_id>/delegate", methods=["POST"])
@require_level("L3")
def delegate_incident(inc_id):
    user = get_current_user()
    target_user  = request.form.get("target_user", "").strip()
    target_level = request.form.get("target_level", "L1")
    note_text    = request.form.get("note", "").strip()
    if not target_user:
        return redirect(url_for("incident_detail", inc_id=inc_id))
    try:
        r = es.get(index="soc-incidents", id=inc_id)
        src = r["_source"]
        old_assignee = src.get("assigned_to", "None")
        src["assigned_to"] = target_user
        src["level"]       = target_level
        src["updated_at"]  = datetime.utcnow().isoformat() + "Z"
        delegation_note = f"[Délégation L3] {old_assignee} → {target_user} ({target_level})"
        if note_text:
            delegation_note += f" — {note_text}"
        src.setdefault("notes", []).append({
            "text":   delegation_note,
            "author": user.get("name", "L3"),
            "at":     datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        })
        es.index(index="soc-incidents", id=inc_id, document=src)
        notifier.notify("assigned", src,
            extra=f"Délégation par L3 : {old_assignee} → {target_user} ({target_level})")
    except Exception:
        pass
    return redirect(url_for("incident_detail", inc_id=inc_id))


# ─── LOG DETAIL ───────────────────────────────────────────────────────────────

@app.route("/logs/<path:index_name>/<doc_id>")
@require_auth
def log_detail(index_name, doc_id):
    user = get_current_user()
    try:
        r = es.get(index=index_name, id=doc_id)
        log = {"_id": r["_id"], "_index": r["_index"], **r["_source"]}
    except Exception:
        return render_template("404.html"), 404

    src_ip = log.get("src_ip", "")

    # Related logs from same IP (last 24h)
    related_logs = []
    if src_ip:
        try:
            r2 = es.search(
                index="soc-logs*",
                query={"bool": {"must": [
                    {"term": {"src_ip": src_ip}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ], "must_not": [{"ids": {"values": [doc_id]}}]}},
                sort=[{"@timestamp": {"order": "desc"}}],
                size=15
            )
            related_logs = [{"_id": h["_id"], "_index": h["_index"], **h["_source"]} for h in r2["hits"]["hits"]]
        except Exception:
            pass

    # Related active incidents from same IP
    related_incidents = []
    if src_ip:
        try:
            r3 = es.search(
                index="soc-incidents",
                query={"bool": {"must": [{"term": {"src_ip": src_ip}}],
                                "must_not": [{"term": {"status": "closed"}}]}},
                sort=[{"created_at": {"order": "desc"}}],
                size=5
            )
            related_incidents = [{"id": h["_id"], **h["_source"]} for h in r3["hits"]["hits"]]
        except Exception:
            pass

    return render_template("log_detail.html",
        log=log, related_logs=related_logs, related_incidents=related_incidents,
        current_user=user)


# ─── MODEL DRIFT DETECTION ───────────────────────────────────────────────────

@app.route("/api/model_drift")
@require_level("L2")
def api_model_drift():
    """Detect model drift: compare avg IF score this week vs last week.
    A significant rise means the model may be under-detecting new attack patterns."""
    try:
        def avg_score(gte, lte):
            r = es.search(index="soc-anomalies", size=0,
                query={"range": {"@timestamp": {"gte": gte, "lte": lte}}},
                aggs={"avg": {"avg": {"field": "anomaly_score"}}})
            return round(r["aggregations"]["avg"]["value"] or 0, 4)

        this_week = avg_score("now-7d", "now")
        last_week = avg_score("now-14d", "now-7d")
        delta = round(this_week - last_week, 4)
        pct   = round((delta / last_week * 100) if last_week else 0, 1)

        # Count anomalies per day for the last 14 days (trend chart)
        trend_r = es.search(index="soc-anomalies", size=0,
            query={"range": {"@timestamp": {"gte": "now-14d"}}},
            aggs={"per_day": {"date_histogram": {"field": "@timestamp",
                                                  "calendar_interval": "day",
                                                  "format": "yyyy-MM-dd"}}})
        trend = [{"date": b["key_as_string"], "count": b["doc_count"]}
                 for b in trend_r["aggregations"]["per_day"]["buckets"]]

        alert = pct > 20  # >20% rise = drift alert
        return jsonify({
            "this_week_avg": this_week,
            "last_week_avg": last_week,
            "delta":         delta,
            "pct_change":    pct,
            "drift_alert":   alert,
            "trend":         trend,
            "message": f"⚠️ Dérive détectée : +{pct}% vs semaine dernière" if alert else f"✅ Stable ({pct:+.1f}%)"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── TASK CHECKLIST ──────────────────────────────────────────────────────────

PLAYBOOK_TASKS = {
    "brute_force":   ["Bloquer IP source (iptables DROP)", "Vérifier les comptes compromis", "Analyser les logs SSH des 24h", "Réinitialiser les mots de passe affectés", "Activer fail2ban si absent"],
    "web_attack":    ["Bloquer IP en WAF", "Analyser les requêtes HTTP suspectes", "Vérifier les fichiers uploadés", "Scanner les vulnérabilités web", "Patcher CVE si identifié"],
    "ids_alert":     ["Confirmer le vrai positif", "Isoler le host si nécessaire", "Capturer le trafic réseau (tcpdump)", "Analyser la charge utile"],
    "anomaly_ia":    ["Corréler avec les logs bruts", "Vérifier l'IP sur VirusTotal", "Comparer avec baseline normale", "Escalader si score > 8"],
    "cve":           ["Identifier les systèmes exposés", "Appliquer le patch ou workaround", "Scanner tous les hôtes concernés", "Documenter la remédiation"],
    "scan":          ["Identifier la source du scan", "Vérifier si scan interne ou externe", "Bloquer l'IP si malveillant", "Auditer les ports ouverts"],
}

@app.route("/api/incidents/<inc_id>/tasks", methods=["GET"])
@require_auth
def get_incident_tasks(inc_id):
    user = get_current_user()
    if not user: return jsonify({"error": "unauth"}), 401
    try:
        doc = es.get(index="soc-incidents", id=inc_id)
        tasks = doc["_source"].get("tasks", [])
        return jsonify({"tasks": tasks})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/incidents/<inc_id>/tasks", methods=["POST"])
@require_level("L1")
def add_incident_task(inc_id):
    user = get_current_user()
    data = request.get_json() or {}
    text = (data.get("text") or "").strip()
    if not text: return jsonify({"error": "text required"}), 400
    task = {
        "id": str(uuid.uuid4())[:8],
        "text": text,
        "done": False,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "created_by": user["username"]
    }
    try:
        es.update(index="soc-incidents", id=inc_id, body={
            "script": {
                "source": "if (ctx._source.tasks == null) { ctx._source.tasks = [] } ctx._source.tasks.add(params.task)",
                "params": {"task": task}
            }
        })
        audit_log("add_task", user=user["username"], details={"incident_id": inc_id, "task": text})
        return jsonify({"status": "ok", "task": task})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/incidents/<inc_id>/tasks/<task_id>/toggle", methods=["POST"])
@require_level("L1")
def toggle_incident_task(inc_id, task_id):
    user = get_current_user()
    try:
        es.update(index="soc-incidents", id=inc_id, body={
            "script": {
                "source": """
                    for (int i=0; i < ctx._source.tasks.size(); i++) {
                        if (ctx._source.tasks[i].id == params.task_id) {
                            boolean now_done = !ctx._source.tasks[i].done;
                            ctx._source.tasks[i].done = now_done;
                            ctx._source.tasks[i].done_at = now_done ? params.now : null;
                            ctx._source.tasks[i].done_by = now_done ? params.user : null;
                        }
                    }
                """,
                "params": {"task_id": task_id, "now": datetime.utcnow().isoformat() + "Z", "user": user["username"]}
            }
        })
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/incidents/<inc_id>/tasks/<task_id>", methods=["DELETE"])
@require_level("L2")
def delete_incident_task(inc_id, task_id):
    try:
        es.update(index="soc-incidents", id=inc_id, body={
            "script": {
                "source": "ctx._source.tasks.removeIf(t -> t.id == params.task_id)",
                "params": {"task_id": task_id}
            }
        })
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/incidents/<inc_id>/tasks/seed", methods=["POST"])
@require_level("L1")
def seed_incident_tasks(inc_id):
    """Auto-populate tasks from playbook based on incident type."""
    user = get_current_user()
    try:
        doc = es.get(index="soc-incidents", id=inc_id)
        inc_type = doc["_source"].get("type", "")
        existing = doc["_source"].get("tasks", [])
        if existing:
            return jsonify({"status": "already_has_tasks", "count": len(existing)})
        templates = PLAYBOOK_TASKS.get(inc_type, PLAYBOOK_TASKS["anomaly_ia"])
        tasks = [{
            "id": str(uuid.uuid4())[:8],
            "text": t,
            "done": False,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "created_by": "playbook"
        } for t in templates]
        es.update(index="soc-incidents", id=inc_id, body={"doc": {"tasks": tasks}})
        audit_log("seed_tasks", user=user["username"], details={"incident_id": inc_id, "count": len(tasks)})
        return jsonify({"status": "ok", "tasks": tasks})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── AUTO MITIGATION ─────────────────────────────────────────────────────────

@app.route("/api/incidents/<inc_id>/mitigate", methods=["POST"])
@require_level("L2")
def auto_mitigate(inc_id):
    """Apply iptables block for the incident's src_ip. L2+ only. Lab use."""
    user = get_current_user()
    try:
        doc = es.get(index="soc-incidents", id=inc_id)
        src_ip = doc["_source"].get("src_ip", "")
        if not src_ip:
            return jsonify({"error": "Pas d'IP source dans cet incident"}), 400
        # Safety: never block localhost, SOC itself, or private nets we depend on
        forbidden = ("127.", "::1", "192.168.50.10")
        if any(src_ip.startswith(p) for p in forbidden):
            return jsonify({"error": f"Blocage de {src_ip} refusé (IP protégée)"}), 403

        result = subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return jsonify({"error": result.stderr.strip()}), 500

        # Persist mitigation in incident notes
        doc_src = doc["_source"]
        note = f"[MITIGATION AUTO] iptables DROP appliqué pour {src_ip} par {user['name']}"
        doc_src.setdefault("notes", []).append({
            "text": note, "author": user["name"],
            "at": datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        })
        doc_src["mitigated_at"] = datetime.utcnow().isoformat() + "Z"
        doc_src["mitigated_by"] = user["username"]
        doc_src["updated_at"]   = datetime.utcnow().isoformat() + "Z"
        es.index(index="soc-incidents", id=inc_id, document=doc_src)
        # Track blocked IP in dedicated index for NIST coverage metrics
        try:
            es.index(index="soc-blocked-ips", document={
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "ip": src_ip,
                "blocked_by": user["username"],
                "incident_id": inc_id,
                "method": "iptables_DROP",
                "active": True,
            })
        except Exception as e_blk:
            app.logger.warning(f"soc-blocked-ips index failed: {e_blk}")
        audit_log("auto_mitigate", details={"incident_id": inc_id, "blocked_ip": src_ip})
        return jsonify({"status": "ok", "message": f"IP {src_ip} bloquée via iptables DROP"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents/<inc_id>/send_email", methods=["POST"])
@require_level("L2")
def send_incident_email(inc_id):
    """Envoi manuel d'un email de notification pour un incident donné."""
    try:
        doc = es.get(index="soc-incidents", id=inc_id)
        src = doc["_source"]
        src["incident_id"] = inc_id
        result = notifier.send_email("assigned", src)
        if result:
            to_email, _ = notifier.get_recipient(src)
            return jsonify({"status": "ok", "message": f"Email envoyé → {to_email}"})
        else:
            return jsonify({"status": "error", "message": "Échec envoi — vérifier config SMTP"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/soar/block_ip", methods=["POST"])
@require_level("L2")
def soar_block_ip_manual():
    """Bloquer manuellement une IP via iptables (sans incident). L2+ requis."""
    import ipaddress
    user = get_current_user()
    data = request.get_json(force=True) or {}
    src_ip = (data.get("ip") or "").strip()
    reason = (data.get("reason") or "Blocage manuel").strip()[:200]
    if not src_ip:
        return jsonify({"error": "ip requis"}), 400
    try:
        ipaddress.ip_address(src_ip)
    except ValueError:
        return jsonify({"error": "Format IP invalide"}), 400
    forbidden = ("127.", "::1", "0.0.0.0")
    if any(src_ip.startswith(p) for p in forbidden):
        return jsonify({"error": f"IP protégée — blocage refusé"}), 403
    result = subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        return jsonify({"error": result.stderr.strip() or "Erreur iptables"}), 500
    try:
        es.index(index="soc-blocked-ips", document={
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "ip": src_ip,
            "blocked_by": user["username"],
            "incident_id": None,
            "reason": reason,
            "method": "iptables_DROP_manual",
            "active": True,
        })
    except Exception as e_blk:
        app.logger.warning(f"soc-blocked-ips index failed: {e_blk}")
    audit_log("soar_block_ip_manual", details={"ip": src_ip, "reason": reason})
    return jsonify({"status": "ok", "message": f"IP {src_ip} bloquée via iptables DROP"})


@app.route("/api/mitigate_unblock", methods=["POST"])
@require_level("L3")
def mitigate_unblock():
    """Remove an iptables DROP rule for an IP. L3 only."""
    import ipaddress
    src_ip = (request.json or {}).get("ip", "")
    if not src_ip:
        return jsonify({"error": "ip required"}), 400
    try:
        ipaddress.ip_address(src_ip)
    except ValueError:
        return jsonify({"error": "format IP invalide"}), 400
    result = subprocess.run(
        ["sudo", "iptables", "-D", "INPUT", "-s", src_ip, "-j", "DROP"],
        capture_output=True, text=True, timeout=10
    )
    audit_log("mitigate_unblock", details={"ip": src_ip, "rc": result.returncode})
    return jsonify({"status": "ok" if result.returncode == 0 else "not_found"})


# ─── PRIORITISATION & QUEUE SOC ──────────────────────────────────────────────

@app.route("/api/priority_queue")
@require_auth
def api_priority_queue():
    """
    Retourne les incidents ouverts triés par score de priorité composite :
    sévérité (40%) + score IA (35%) + âge (25%) + bonus llama3.
    Optionnel : ?assignee=<name> pour filtrer par analyste.
    """
    user = get_current_user()
    assignee_filter = request.args.get("assignee", "")

    try:
        query = {"bool": {"must_not": [{"term": {"status": "closed"}}]}}
        if assignee_filter:
            query["bool"]["must"] = [{"term": {"assigned_to": assignee_filter}}]
        elif user["level"] == "L1":
            # L1 voit seulement ses propres incidents
            query["bool"]["must"] = [{"term": {"assigned_to": user["name"]}}]

        r = es.search(index="soc-incidents", size=200, query=query,
                      _source=["incident_id", "title", "severity", "status",
                                "assigned_to", "level", "unified_score", "src_ip",
                                "created_at", "updated_at", "llm_confidence",
                                "llm_verdict", "type", "auto_labeled"])
        incidents = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            priority = compute_priority_score(
                severity       = s.get("severity", "medium"),
                score          = s.get("unified_score", 0),
                created_at     = s.get("created_at", ""),
                llm_confidence = s.get("llm_confidence"),
            )
            # Âge en minutes
            try:
                created = datetime.fromisoformat(s.get("created_at","").replace("Z","+00:00"))
                age_min = int((datetime.now(timezone.utc) - created).total_seconds() / 60)
            except Exception:
                age_min = 0

            # SLA restant en minutes
            sla = {"critical": 15, "high": 60, "medium": 240, "low": 1440}
            sla_minutes = sla.get(s.get("severity","medium"), 240)
            sla_remaining = max(0, sla_minutes - age_min)
            sla_breached  = age_min > sla_minutes

            incidents.append({
                "id":            h["_id"],
                "incident_id":   s.get("incident_id",""),
                "title":         s.get("title",""),
                "severity":      s.get("severity","medium"),
                "status":        s.get("status",""),
                "assigned_to":   s.get("assigned_to",""),
                "level":         s.get("level",""),
                "score":         s.get("unified_score", 0),
                "src_ip":        s.get("src_ip",""),
                "type":          s.get("type",""),
                "llm_verdict":   s.get("llm_verdict",""),
                "auto_labeled":  s.get("auto_labeled", False),
                "age_min":       age_min,
                "sla_remaining": sla_remaining,
                "sla_breached":  sla_breached,
                "priority":      priority,
            })

        # Trier : SLA breached en premier, puis par score de priorité desc
        incidents.sort(key=lambda x: (-int(x["sla_breached"]), -x["priority"]))
        return jsonify({"incidents": incidents, "total": len(incidents)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/meta_learner/stats")
@require_auth
def api_meta_learner_stats():
    """Retourne les stats du meta-learner (précision par modèle)."""
    try:
        import meta_learner
        stats = meta_learner.load_stats()
        if not stats:
            return jsonify({"status": "not_trained",
                            "message": "Meta-learner non encore entraîné — pas assez de verdicts llama3"})
        return jsonify({"status": "ok", **stats})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/meta_learner/train", methods=["POST"])
@require_level("L3")
def api_meta_learner_train():
    """Déclenche l'entraînement du meta-learner (L3 only)."""
    def _train():
        import meta_learner
        meta_learner.train()
    threading.Thread(target=_train, daemon=True).start()
    audit_log("meta_learner_train")
    return jsonify({"status": "training_started"})


@app.route("/queue")
@require_auth
def queue_page():
    return render_template("queue.html", current_user=get_current_user())


# ─── STEALTH COMPARE ─────────────────────────────────────────────────────────

@app.route("/stealth_compare")
@require_level("L2")
def stealth_compare_page():
    return render_template("stealth_compare.html", current_user=get_current_user())


@app.route("/api/stealth_compare/detections")
@require_level("L2")
def api_stealth_detections():
    """
    Attaques stealth = détectées par IA Ensemble (score ≥ 0.30) MAIS
    en dessous du seuil statique Kibana (rate < KIBANA_THRESHOLD).
    Retourne aussi les attaques normales pour comparaison.
    """
    window            = request.args.get("window", "7d")
    KIBANA_THRESHOLD  = 10   # seuil Kibana : 10 auth/1min (max_rate_1m)

    try:
        # ── Tous les événements détectés par IA OU par Kibana (OR logic) ─
        # Kibana détecte si rate_count >= seuil ; IA détecte si ensemble_score >= 0.28
        r = es.search(
            index="soc-ensemble-anomalies",
            size=500,
            query={"bool": {
                "must": [{"range": {"@timestamp": {"gte": f"now-{window}"}}}],
                "should": [
                    {"range": {"ensemble_score": {"gte": 0.28}}},
                    {"range": {"rate_count":     {"gte": KIBANA_THRESHOLD}}},
                ],
                "minimum_should_match": 1,
            }},
            sort=[{"@timestamp": {"order": "desc"}}],
            _source=["@timestamp", "src_ip", "ensemble_score", "if_score", "rf_score",
                     "dl_score", "rate_count", "votes", "severity", "log_type"],
        )
        hits = r["hits"]["hits"]

        # Enrichir avec verdict LLM
        llm_map = {}
        if hits:
            ips = list({h["_source"].get("src_ip") for h in hits if h["_source"].get("src_ip")})
            try:
                inc_r = es.search(
                    index="soc-incidents", size=300,
                    query={"bool": {"must": [
                        {"terms": {"src_ip": ips}},
                        {"range": {"created_at": {"gte": f"now-{window}"}}},
                    ]}},
                    _source=["src_ip", "llm_verdict", "llm_confidence",
                             "mitre_tactic", "mitre_technique", "related_cves", "max_cvss",
                             "title", "attack_type"],
                )
                for ih in inc_r["hits"]["hits"]:
                    s = ih["_source"]
                    ip = s.get("src_ip")
                    if ip and ip not in llm_map:
                        llm_map[ip] = {
                            "llm_verdict":     s.get("llm_verdict"),
                            "llm_confidence":  s.get("llm_confidence"),
                            "mitre_tactic":    s.get("mitre_tactic", ""),
                            "mitre_technique": s.get("mitre_technique", ""),
                            "related_cves":    s.get("related_cves", []),
                            "max_cvss":        s.get("max_cvss"),
                            "attack_type":     s.get("attack_type", ""),
                        }
            except Exception:
                pass

        stealth       = []   # IA détecte, Kibana manque  (score≥0.28 ET rate<seuil)
        detected_both = []   # les deux détectent          (score≥0.28 ET rate≥seuil)
        kibana_only   = []   # Kibana détecte, IA manque  (rate≥seuil ET score<0.28)

        for h in hits:
            s      = h["_source"]
            ip     = s.get("src_ip")
            rate   = int(s.get("rate_count") or 0)
            max_1m = int(s.get("max_rate_1m") or 0)
            sc     = float(s.get("ensemble_score") or 0)
            ia_detects     = sc    >= 0.28
            # Kibana déclenche si max par minute >= seuil (10/1min)
            # Si max_rate_1m pas encore stocké (anciens docs), fallback sur rate_count/5
            kibana_detects = (max_1m >= KIBANA_THRESHOLD) if max_1m > 0 else (rate >= KIBANA_THRESHOLD * 5)
            det = {
                "src_ip":         ip,
                "timestamp":      s.get("@timestamp"),
                "ensemble_score": sc,
                "if_score":       s.get("if_score"),
                "rf_score":       s.get("rf_score"),
                "dl_score":       s.get("dl_score"),
                "rate_count":     rate,
                "max_rate_1m":    max_1m,
                "votes":          s.get("votes"),
                "severity":       s.get("severity"),
                "log_type":       s.get("log_type"),
                **llm_map.get(ip, {}),
                "ia_detects":     ia_detects,
                "kibana_detects": kibana_detects,
            }
            if ia_detects and not kibana_detects:
                stealth.append(det)
            elif ia_detects and kibana_detects:
                detected_both.append(det)
            else:
                # rate >= seuil mais score IA < 0.28 → Kibana seul
                kibana_only.append(det)

        # ── Timeline stealth : répartition horaire ──────────────────────
        timeline = []
        try:
            tl = es.search(
                index="soc-ensemble-anomalies", size=0,
                query={"bool": {"must": [
                    {"range": {"@timestamp":    {"gte": f"now-{window}"}}},
                    {"range": {"ensemble_score": {"gte": 0.28}}},
                ], "should": [
                    {"range": {"max_rate_1m": {"lt": KIBANA_THRESHOLD}}},
                    {"bool": {"must_not": {"exists": {"field": "max_rate_1m"}},
                              "must": [{"range": {"rate_count": {"lt": KIBANA_THRESHOLD * 5}}}]}}
                ], "minimum_should_match": 1}},
                aggs={"per_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "1h",
                        "min_doc_count": 0,
                    }
                }}
            )
            for b in tl["aggregations"]["per_hour"]["buckets"]:
                timeline.append({"hour": b["key_as_string"][:16], "count": b["doc_count"]})
        except Exception:
            pass

        return jsonify({
            "stealth":          stealth,
            "detected_both":    detected_both,
            "kibana_only":      kibana_only,
            "timeline":         timeline,
            "total_stealth":    len(stealth),
            "total_both":       len(detected_both),
            "total_kibana_only": len(kibana_only),
            "kibana_threshold": KIBANA_THRESHOLD,
            "window":           window,
        })

    except Exception as e:
        return jsonify({"error": str(e), "stealth": [], "detected_both": [],
                        "total_stealth": 0, "total_both": 0, "timeline": []})


# ─── PIPELINE COMPARE ────────────────────────────────────────────────────────

@app.route("/pipeline_compare")
@require_level("L2")
def pipeline_compare_page():
    return render_template("pipeline_compare.html", current_user=get_current_user())


@app.route("/api/pipeline_compare/kibana")
@require_level("L2")
def api_pipeline_kibana():
    """
    Pipeline 1: raw auth log volume per IP (what Kibana static rules would catch).
    Groups soc-logs-* auth logs by src_ip in the requested window.
    """
    window = request.args.get("window", "1h")
    try:
        r = es.search(
            index="soc-logs*",
            size=0,
            query={"bool": {"must": [
                {"range": {"@timestamp": {"gte": f"now-{window}"}}},
                {"term":  {"log_type": "auth"}},
            ]}},
            aggs={"by_ip": {
                "terms": {"field": "src_ip", "size": 50, "order": {"_count": "desc"}},
                "aggs": {
                    "latest": {"max": {"field": "@timestamp"}},
                    "log_types": {"terms": {"field": "log_type", "size": 5}},
                }
            }}
        )
        KIBANA_THRESHOLD = 10   # same as rate detector: 10 auth/window → alert
        alerts = []
        for b in r["aggregations"]["by_ip"]["buckets"]:
            ip    = b["key"]
            count = b["doc_count"]
            if count < KIBANA_THRESHOLD:
                continue
            alerts.append({
                "src_ip":    ip,
                "count":     count,
                "log_type":  "auth",
                "timestamp": b["latest"]["value_as_string"] if b["latest"].get("value_as_string") else None,
            })
        return jsonify({"alerts": alerts, "total": len(alerts), "window": window})
    except Exception as e:
        return jsonify({"error": str(e), "alerts": [], "total": 0})


@app.route("/api/pipeline_compare/ia")
@require_level("L2")
def api_pipeline_ia():
    """
    Pipeline 2: IA Ensemble detections (soc-ensemble-anomalies) with llm_verdict from soc-incidents.
    """
    window = request.args.get("window", "1h")
    try:
        r = es.search(
            index="soc-ensemble-anomalies",
            size=100,
            query={"range": {"@timestamp": {"gte": f"now-{window}"}}},
            sort=[{"@timestamp": {"order": "desc"}}],
            _source=["@timestamp", "src_ip", "ensemble_score", "if_score", "rf_score",
                     "dl_score", "rate_count", "votes", "severity", "log_type"],
        )
        hits = r["hits"]["hits"]

        # Enrich with llm_verdict from soc-incidents (last match per IP)
        llm_map = {}
        if hits:
            ips = list({h["_source"].get("src_ip") for h in hits if h["_source"].get("src_ip")})
            try:
                inc_r = es.search(
                    index="soc-incidents",
                    size=200,
                    query={"bool": {"must": [
                        {"terms": {"src_ip": ips}},
                        {"range": {"created_at": {"gte": f"now-{window}"}}},
                    ]}},
                    _source=["src_ip", "llm_verdict", "llm_confidence"],
                )
                for ih in inc_r["hits"]["hits"]:
                    s  = ih["_source"]
                    ip = s.get("src_ip")
                    if ip and ip not in llm_map:
                        llm_map[ip] = {
                            "llm_verdict":     s.get("llm_verdict"),
                            "llm_confidence":  s.get("llm_confidence"),
                        }
            except Exception:
                pass

        detections = []
        for h in hits:
            s  = h["_source"]
            ip = s.get("src_ip")
            det = {
                "src_ip":         ip,
                "timestamp":      s.get("@timestamp"),
                "ensemble_score": s.get("ensemble_score"),
                "if_score":       s.get("if_score"),
                "rf_score":       s.get("rf_score"),
                "dl_score":       s.get("dl_score"),
                "rate_count":     s.get("rate_count"),
                "votes":          s.get("votes"),
                "severity":       s.get("severity"),
                "log_type":       s.get("log_type"),
                "llm_verdict":    llm_map.get(ip, {}).get("llm_verdict"),
                "llm_confidence": llm_map.get(ip, {}).get("llm_confidence"),
            }
            detections.append(det)

        return jsonify({"detections": detections, "total": len(detections), "window": window})
    except Exception as e:
        return jsonify({"error": str(e), "detections": [], "total": 0})


# ─── IN-APP NOTIFICATIONS ───────────────────────────────────────────────────

@app.route("/api/notifications")
@require_auth
def api_get_notifications():
    """Retourne les notifications non lues de l'utilisateur connecté."""
    user = get_current_user()
    username = user["username"]
    try:
        r = es.search(
            index="soc-notifications",
            size=30,
            query={"bool": {"must": [
                {"term": {"read": False}},
                {"bool": {"should": [
                    {"term": {"recipient": username}},
                    {"term": {"recipient": "all"}},
                ], "minimum_should_match": 1}}
            ]}},
            sort=[{"@timestamp": {"order": "desc"}}],
            _source=["@timestamp", "recipient", "message", "type", "incident_id", "severity", "read"]
        )
        notifs = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            notifs.append({
                "id":          h["_id"],
                "message":     s.get("message", ""),
                "type":        s.get("type", "info"),
                "incident_id": s.get("incident_id"),
                "severity":    s.get("severity"),
                "ts":          (s.get("@timestamp") or "")[:16].replace("T", " "),
            })
        return jsonify({"notifications": notifs, "unread": len(notifs)})
    except Exception as e:
        return jsonify({"notifications": [], "unread": 0})


@app.route("/api/notifications/read", methods=["POST"])
@require_auth
def api_mark_notifications_read():
    """Marque une ou toutes les notifications comme lues."""
    data = request.get_json(force=True) or {}
    notif_id = data.get("id")   # si None → marquer tout
    user = get_current_user()
    username = user["username"]
    try:
        if notif_id:
            es.update(index="soc-notifications", id=notif_id, body={"doc": {"read": True}})
        else:
            # Marquer tout d'un coup via update_by_query
            es.update_by_query(index="soc-notifications", body={
                "script": {"source": "ctx._source.read = true"},
                "query": {"bool": {"must": [
                    {"term": {"read": False}},
                    {"bool": {"should": [
                        {"term": {"recipient": username}},
                        {"term": {"recipient": "all"}},
                    ], "minimum_should_match": 1}}
                ]}}
            })
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ─── ADMIN — NOTIFICATIONS ───────────────────────────────────────────────────

NOTIF_LOG_PATH = os.path.join(os.path.dirname(__file__), "notifications_log.json")


def _notif_log_append(event_type, incident_id, channels):
    """Persiste un enregistrement de notification envoyée."""
    try:
        try:
            with open(NOTIF_LOG_PATH) as f:
                log_data = json.load(f)
        except Exception:
            log_data = []
        log_data.append({
            "ts":          datetime.now(timezone.utc).isoformat(),
            "event":       event_type,
            "incident_id": incident_id,
            "channels":    channels,
        })
        if len(log_data) > 200:
            log_data = log_data[-200:]
        with open(NOTIF_LOG_PATH, "w") as f:
            json.dump(log_data, f)
    except Exception:
        pass


# Monkey-patch notifier.notify to log results
_orig_notify = notifier.notify
def _notify_with_log(event_type, incident, extra=None, async_send=True):
    cfg = notifier.load_config()
    sev = incident.get("severity", "medium")
    if event_type == "new_incident" and sev not in cfg.get("notify_severities", ["critical","high"]):
        return _orig_notify(event_type, incident, extra, async_send)
    def _wrapped():
        channels = {}
        if cfg.get("email", {}).get("enabled"):
            channels["email"]   = notifier.send_email(event_type, incident, extra)
        if cfg.get("webhook", {}).get("enabled"):
            channels["webhook"] = notifier.send_webhook(event_type, incident, extra)
        _notif_log_append(event_type, incident.get("incident_id", "?"), channels)
    if async_send:
        threading.Thread(target=_wrapped, daemon=True).start()
    else:
        _wrapped()
notifier.notify = _notify_with_log


@app.route("/notifications")
@require_auth
def notifications_page():
    """Page historique complet des notifications in-app de l'utilisateur connecté."""
    return render_template("notifications.html", current_user=get_current_user())


@app.route("/api/notifications/history")
@require_auth
def api_notifications_history():
    """Retourne TOUT l'historique des notifications (lues + non lues) de l'utilisateur."""
    user = get_current_user()
    username = user["username"]
    page = int(request.args.get("page", 1))
    size = 50
    offset = (page - 1) * size
    try:
        r = es.search(
            index="soc-notifications",
            size=size,
            from_=offset,
            query={"bool": {"should": [
                {"term": {"recipient": username}},
                {"term": {"recipient": "all"}},
            ], "minimum_should_match": 1}},
            sort=[{"@timestamp": {"order": "desc"}}],
            _source=["@timestamp", "recipient", "message", "type", "incident_id", "severity", "read"]
        )
        total = r["hits"]["total"]["value"]
        notifs = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            notifs.append({
                "id":          h["_id"],
                "message":     s.get("message", ""),
                "type":        s.get("type", "info"),
                "incident_id": s.get("incident_id"),
                "severity":    s.get("severity"),
                "read":        s.get("read", False),
                "ts":          (s.get("@timestamp") or "")[:19].replace("T", " "),
            })
        return jsonify({"notifications": notifs, "total": total, "page": page})
    except Exception as e:
        return jsonify({"notifications": [], "total": 0, "page": 1})


@app.route("/emailing")
@require_level("L2")
def emailing_page():
    """Page historique des emails envoyés automatiquement par la plateforme."""
    return render_template("emailing.html", current_user=get_current_user())


@app.route("/api/emailing/history")
@require_level("L2")
def api_emailing_history():
    """Retourne l'historique des emails envoyés (depuis notifications_log.json)."""
    try:
        with open(NOTIF_LOG_PATH) as f:
            entries = json.load(f)
        # Filtrer uniquement ceux qui ont un canal email
        email_entries = [e for e in reversed(entries) if e.get("channels", {}).get("email")]
        return jsonify({"entries": email_entries, "total": len(email_entries)})
    except Exception:
        return jsonify({"entries": [], "total": 0})


@app.route("/admin/notifications")
@require_level("L3")
def admin_notifications_page():
    return render_template("admin_notifications.html", current_user=get_current_user())


@app.route("/api/admin/notifications/config", methods=["GET", "POST"])
@require_level("L3")
def api_notif_config():
    if request.method == "GET":
        return jsonify(notifier.load_config())
    data = request.get_json(force=True)
    try:
        notifier.save_config(data)
        audit_log("notif_config_update", details={"channels": {
            "email":   data.get("email", {}).get("enabled"),
            "webhook": data.get("webhook", {}).get("enabled"),
        }})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/admin/notifications/test", methods=["POST"])
@require_level("L3")
def api_notif_test():
    results = notifier.test_notifications()
    _notif_log_append("test", "INC-TEST", results)
    return jsonify(results)


@app.route("/api/admin/notifications/log")
@require_level("L3")
def api_notif_log():
    try:
        with open(NOTIF_LOG_PATH) as f:
            entries = json.load(f)
        return jsonify({"entries": list(reversed(entries[-50:]))})
    except Exception:
        return jsonify({"entries": []})


# ─── POST-EXPLOIT / KILL CHAIN ───────────────────────────────────────────────

@app.route("/postexploit")
@require_level("L2")
def postexploit_page():
    return render_template("postexploit.html")


@app.route("/api/postexploit/stats")
@require_level("L2")
def api_postexploit_stats():
    try:
        total = es.count(index="soc-postexploit-events")["count"]
        r = es.search(index="soc-postexploit-events", size=0, query={"match_all": {}}, aggs={
            "by_technique": {"terms": {"field": "technique", "size": 15}},
            "by_severity":  {"terms": {"field": "severity",  "size": 5}},
            "by_ip":        {"terms": {"field": "src_ip",    "size": 10}},
            "last_24h":     {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}},
        })
        agg = r["aggregations"]
        return jsonify({
            "total":        total,
            "last_24h":     agg["last_24h"]["doc_count"],
            "by_technique": {b["key"]: b["doc_count"] for b in agg["by_technique"]["buckets"]},
            "by_severity":  {b["key"]: b["doc_count"] for b in agg["by_severity"]["buckets"]},
            "by_ip":        [{"ip": b["key"], "count": b["doc_count"]} for b in agg["by_ip"]["buckets"]],
        })
    except Exception as e:
        return jsonify({"total": 0, "last_24h": 0, "by_technique": {}, "by_severity": {}, "by_ip": [], "error": str(e)})


@app.route("/api/postexploit/sessions")
@require_level("L2")
def api_postexploit_sessions():
    """Retourne les IPs avec activité post-exploit, groupées par session."""
    window = request.args.get("window", "24h")
    try:
        r = es.search(index="soc-postexploit-events", size=0,
            query={"range": {"@timestamp": {"gte": f"now-{window}"}}},
            aggs={"by_ip": {"terms": {"field": "src_ip", "size": 20},
                "aggs": {
                    "techniques":    {"terms": {"field": "technique", "size": 15}},
                    "max_severity":  {"terms": {"field": "severity",  "size": 1, "order": {"_count": "desc"}}},
                    "first_seen":    {"min": {"field": "@timestamp"}},
                    "last_seen":     {"max": {"field": "@timestamp"}},
                    "event_count":   {"value_count": {"field": "technique"}},
                }
            }}
        )
        sessions = []
        for b in r["aggregations"]["by_ip"]["buckets"]:
            ip          = b["key"]
            techniques  = [t["key"] for t in b["techniques"]["buckets"]]
            max_sev     = b["max_severity"]["buckets"][0]["key"] if b["max_severity"]["buckets"] else "medium"
            first_seen  = b["first_seen"]["value_as_string"][:19].replace("T", " ") if b["first_seen"]["value"] else ""
            last_seen   = b["last_seen"]["value_as_string"][:19].replace("T", " ")  if b["last_seen"]["value"]  else ""
            event_count = b["event_count"]["value"]

            # Récupérer aussi le login SSH initial pour cette IP
            ssh_r = es.search(index="soc-logs*", size=1,
                query={"bool": {"must": [
                    {"term": {"src_ip": ip}},
                    {"range": {"@timestamp": {"gte": f"now-{window}"}}},
                ], "should": [
                    {"match_phrase": {"message": "Accepted password"}},
                    {"match_phrase": {"message": "Accepted publickey"}},
                ], "minimum_should_match": 1}},
                sort=[{"@timestamp": "asc"}], _source=["@timestamp", "message", "ssh_user"]
            )
            ssh_login = None
            if ssh_r["hits"]["hits"]:
                sl = ssh_r["hits"]["hits"][0]["_source"]
                ssh_login = {
                    "ts":   sl.get("@timestamp", "")[:19].replace("T", " "),
                    "user": sl.get("ssh_user", ""),
                    "msg":  sl.get("message", "")[:80],
                }

            sessions.append({
                "ip":          ip,
                "techniques":  techniques,
                "max_severity":max_sev,
                "first_seen":  first_seen,
                "last_seen":   last_seen,
                "event_count": event_count,
                "ssh_login":   ssh_login,
            })

        sessions.sort(key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s["max_severity"], 0), reverse=True)
        return jsonify({"sessions": sessions, "total": len(sessions)})
    except Exception as e:
        return jsonify({"sessions": [], "total": 0, "error": str(e)})


@app.route("/api/postexploit/killchain/<path:ip>")
@require_level("L2")
def api_postexploit_killchain(ip):
    """Retourne le détail kill chain pour une IP : tous les events triés par temps."""
    window = request.args.get("window", "24h")
    try:
        r = es.search(index="soc-postexploit-events", size=100,
            query={"bool": {"must": [
                {"term":  {"src_ip": ip}},
                {"range": {"@timestamp": {"gte": f"now-{window}"}}},
            ]}},
            sort=[{"@timestamp": "asc"}],
            _source=["@timestamp", "technique", "tactic", "severity", "description",
                     "matched", "message", "color", "log_type", "program"]
        )
        events = [h["_source"] for h in r["hits"]["hits"]]

        # Aussi récupérer les logs bruts autour de chaque event
        for ev in events:
            ev["@timestamp"] = ev.get("@timestamp", "")[:19].replace("T", " ")

        # Récupérer le login SSH initial
        ssh_r = es.search(index="soc-logs*", size=1,
            query={"bool": {"must": [
                {"term": {"src_ip": ip}},
                {"range": {"@timestamp": {"gte": f"now-{window}"}}},
            ], "should": [
                {"match_phrase": {"message": "Accepted password"}},
                {"match_phrase": {"message": "Accepted publickey"}},
            ], "minimum_should_match": 1}},
            sort=[{"@timestamp": "asc"}], _source=["@timestamp", "message", "ssh_user"]
        )
        ssh_login = None
        if ssh_r["hits"]["hits"]:
            sl = ssh_r["hits"]["hits"][0]["_source"]
            ssh_login = {"ts": sl["@timestamp"][:19].replace("T", " "),
                         "user": sl.get("ssh_user", ""), "msg": sl.get("message", "")[:100]}

        # Récupérer brute force avant le login
        bf_r = es.count(index="soc-logs*", query={"bool": {"must": [
            {"term":  {"src_ip": ip}},
            {"range": {"@timestamp": {"gte": f"now-{window}"}}},
            {"match": {"message": "Failed password"}},
        ]}})
        brute_count = bf_r["count"]

        return jsonify({
            "ip":         ip,
            "events":     events,
            "ssh_login":  ssh_login,
            "brute_force_count": brute_count,
        })
    except Exception as e:
        return jsonify({"ip": ip, "events": [], "error": str(e)})


@app.route("/api/postexploit/nist_coverage")
@require_level("L2")
def api_nist_coverage():
    """Retourne la couverture NIST CSF v2.0 du SOC — scores calculés dynamiquement depuis ES."""

    def _count(index, query=None):
        """Count docs in index, return 0 if index missing or error."""
        try:
            if not es.indices.exists(index=index):
                return 0
            kwargs = {"index": index}
            if query:
                kwargs["query"] = query
            return es.count(**kwargs)["count"]
        except Exception:
            return 0

    def _unique_hostnames(index_pattern, window="now-24h"):
        """Count distinct hostnames in a wildcard index pattern."""
        try:
            res = es.search(index=index_pattern, size=0, aggs={
                "hosts": {"terms": {"field": "host.name.keyword", "size": 500}}
            }, query={"range": {"@timestamp": {"gte": window}}})
            buckets = res.get("aggregations", {}).get("hosts", {}).get("buckets", [])
            return len(buckets)
        except Exception:
            try:
                res = es.search(index=index_pattern, size=0, aggs={
                    "hosts": {"terms": {"field": "hostname.keyword", "size": 500}}
                })
                buckets = res.get("aggregations", {}).get("hosts", {}).get("buckets", [])
                return len(buckets)
            except Exception:
                return 0

    def score_to_status(s):
        if s >= 80:   return "ok"
        if s >= 40:   return "partial"
        return "missing"

    def avg_score(scores):
        return round(sum(scores) / len(scores)) if scores else 0

    # ── IDENTIFY ──────────────────────────────────────────────────────────────
    # AM – Asset Management: unique hostnames in soc-logs-*
    try:
        am_hosts = _unique_hostnames("soc-logs*", "now-7d")
        if am_hosts > 2:
            am_score, am_status, am_detail = 100, "ok",     f"{am_hosts} hôtes distincts inventoriés dans soc-logs-*"
        elif am_hosts >= 1:
            am_score, am_status, am_detail = 80,  "ok",     f"{am_hosts} hôte(s) monitoré(s) — inventaire actif (mini-SOC)"
        else:
            am_score, am_status, am_detail = 0,   "missing", "Aucun hôte détecté dans soc-logs-*"
    except Exception:
        am_score, am_status, am_detail = 0, "missing", "Erreur lecture soc-logs-*"

    # RA – Risk Assessment: CVE alerts
    cve_count = _count("soc-cve-alerts")
    if cve_count > 10:
        ra_score, ra_status, ra_detail = 100, "ok",     f"{cve_count} alertes CVE analysées dans soc-cve-alerts"
    elif cve_count > 0:
        ra_score, ra_status, ra_detail = 80,  "ok",     f"{cve_count} alertes CVE dans soc-cve-alerts"
    else:
        ra_score, ra_status, ra_detail = 40,  "partial", "CVE scanner configuré — aucune alerte indexée"

    # RA2 – Threat Intel / human labels
    label_count = _count("soc-anomaly-labels")
    if label_count > 50:
        ra2_score, ra2_status, ra2_detail = 100, "ok",     f"{label_count} labels TP/FP — threat intel mature"
    elif label_count > 10:
        ra2_score, ra2_status, ra2_detail = 80,  "ok",     f"{label_count} labels TP/FP humains — feedback loop actif"
    elif label_count > 0:
        ra2_score, ra2_status, ra2_detail = 50,  "partial", f"{label_count} labels — démarrage feedback loop"
    else:
        ra2_score, ra2_status, ra2_detail = 0,   "missing", "Aucun label humain — feedback loop inactif"

    # GV – Governance: audit log activity (connexions, actions admin tracées)
    audit_count = _count("soc-audit-log")
    if audit_count > 50:
        gv_score, gv_status, gv_detail = 100, "ok",     f"{audit_count} actions tracées dans soc-audit-log — gouvernance complète"
    elif audit_count > 10:
        gv_score, gv_status, gv_detail = 80,  "ok",     f"{audit_count} entrées d'audit — gouvernance active"
    elif audit_count > 0:
        gv_score, gv_status, gv_detail = 50,  "partial", f"{audit_count} entrées d'audit — gouvernance partielle"
    else:
        gv_score, gv_status, gv_detail = 0,   "missing", "soc-audit-log vide — gouvernance non tracée"

    id_score = avg_score([am_score, ra_score, ra2_score, gv_score])

    # ── PROTECT ───────────────────────────────────────────────────────────────
    # AC – Access Control: RBAC L1/L2/L3 + audit trail
    if audit_count > 50:
        ac_score, ac_status, ac_detail = 100, "ok",  f"RBAC L1/L2/L3 actif — {audit_count} événements d'audit tracés"
    elif audit_count > 0:
        ac_score, ac_status, ac_detail = 80,  "ok",  f"RBAC configuré — {audit_count} événements d'audit"
    else:
        ac_score, ac_status, ac_detail = 40,  "partial", "RBAC L1/L2/L3 configuré — aucun événement tracé"

    # DS – Data Security: IPs bloquées + chiffrement session
    blocked_count = _count("soc-blocked-ips")
    if blocked_count > 5:
        ds_score, ds_status, ds_detail = 100, "ok",     f"{blocked_count} IPs bloquées — isolation réseau active"
    elif blocked_count > 0:
        ds_score, ds_status, ds_detail = 80,  "ok",     f"{blocked_count} IP(s) bloquée(s) — soc-blocked-ips actif"
    else:
        ds_score, ds_status, ds_detail = 20,  "missing", "Aucune IP bloquée — mitigation non déclenchée"

    # MA – Maintenance: CVE résolus + audit comme preuve de revue sécurité
    resolved_cve = _count("soc-cve-alerts", {"term": {"status.keyword": "resolved"}})
    if resolved_cve > 0:
        ma_score, ma_status, ma_detail = 100, "ok",     f"{resolved_cve} CVE résolus — processus de patch actif"
    elif cve_count > 0 and audit_count > 0:
        ma_score, ma_status, ma_detail = 60,  "partial", f"{cve_count} CVE surveillés, {audit_count} audits — revues actives"
    elif audit_count > 0:
        ma_score, ma_status, ma_detail = 40,  "partial", f"Audit log actif ({audit_count} entrées) — maintenance tracée"
    else:
        ma_score, ma_status, ma_detail = 0,   "missing", "Aucune preuve de maintenance sécurité"

    # IP – Infrastructure Protection: blocage auto + détecteurs actifs
    pe_count_pr = _count("soc-postexploit-events")
    if blocked_count > 0 and pe_count_pr > 0:
        ip_score, ip_status, ip_detail = 100, "ok",  f"{blocked_count} IPs bloquées auto — réponse PE active"
    elif blocked_count > 0:
        ip_score, ip_status, ip_detail = 80,  "ok",  f"{blocked_count} IPs bloquées via iptables DROP"
    elif pe_count_pr > 0:
        ip_score, ip_status, ip_detail = 50,  "partial", f"Détection PE active ({pe_count_pr} events) — blocage non encore déclenché"
    else:
        ip_score, ip_status, ip_detail = 20,  "missing", "Aucun blocage automatique actif"

    pr_score = avg_score([ac_score, ds_score, ma_score, ip_score])

    # ── DETECT ────────────────────────────────────────────────────────────────
    # AE – Anomalies & Events: total anomalies last 7d
    try:
        ae_total = (
            _count("soc-anomalies",    {"range": {"@timestamp": {"gte": "now-7d"}}}) +
            _count("soc-dl-anomalies", {"range": {"@timestamp": {"gte": "now-7d"}}}) +
            _count("soc-rf-anomalies", {"range": {"@timestamp": {"gte": "now-7d"}}})
        )
    except Exception:
        ae_total = 0
    if ae_total > 100:
        ae_score, ae_status, ae_detail = 100, "ok",     f"{ae_total} anomalies détectées sur 7j (IF+DL+RF)"
    elif ae_total > 10:
        ae_score, ae_status, ae_detail = 80,  "ok",     f"{ae_total} anomalies ML détectées — pipelines actifs"
    elif ae_total > 0:
        ae_score, ae_status, ae_detail = 60,  "partial", f"{ae_total} anomalies détectées — volume faible"
    else:
        ae_score, ae_status, ae_detail = 0,   "missing", "Aucune anomalie détectée — pipelines ML inactifs ?"

    # CM – Continuous Monitoring: active log sources last 24h
    cm_hosts = _unique_hostnames("soc-logs*", "now-24h")
    if cm_hosts > 1:
        cm_score, cm_status, cm_detail = 100, "ok",  f"{cm_hosts} sources de logs actives dans les 24h"
    elif cm_hosts == 1:
        cm_score, cm_status, cm_detail = 100, "ok",  f"{cm_hosts} source de logs active — surveillance continue opérationnelle"
    else:
        cm_score, cm_status, cm_detail = 0,   "missing", "Aucune source de log active dans les 24h"

    # DP – Detection Process: post-exploit events MITRE ATT&CK
    pe_count = _count("soc-postexploit-events")
    if pe_count > 5:
        dp_score, dp_status, dp_detail = 100, "ok",  f"{pe_count} événements post-exploit MITRE détectés"
    elif pe_count > 0:
        dp_score, dp_status, dp_detail = 80,  "ok",  f"{pe_count} events post-exploit — détection MITRE active"
    else:
        dp_score, dp_status, dp_detail = 30,  "partial", "Pipeline post-exploit actif — aucun event encore"

    # ML – RF anomaly detector active
    rf_count = _count("soc-rf-anomalies")
    if rf_count > 100:
        ml_score, ml_status, ml_detail = 100, "ok",  f"{rf_count} anomalies RF — RandomForest mature"
    elif rf_count > 0:
        ml_score, ml_status, ml_detail = 100, "ok",  f"{rf_count} anomalies RF — détecteur RandomForest actif"
    else:
        ml_score, ml_status, ml_detail = 40,  "partial", "Détecteur RF configuré — aucune anomalie indexée"

    de_score = avg_score([ae_score, cm_score, dp_score, ml_score])

    # ── RESPOND ───────────────────────────────────────────────────────────────
    # RP – Response Planning: incidents in_progress + closed (triage actif)
    inc_active = _count("soc-incidents", {
        "bool": {"should": [
            {"term": {"status": "in_progress"}},
            {"term": {"status": "closed"}}
        ], "minimum_should_match": 1}
    })
    closed_inc = _count("soc-incidents", {"term": {"status": "closed"}})
    if closed_inc > 0 and inc_active > 10:
        rp_score, rp_status, rp_detail = 100, "ok",  f"{inc_active} incidents triés dont {closed_inc} clôturés"
    elif inc_active > 0:
        rp_score, rp_status, rp_detail = 80,  "ok",  f"{inc_active} incidents en cours de triage (in_progress/closed)"
    else:
        rp_score, rp_status, rp_detail = 20,  "partial", "Incidents présents — aucun triage tracé"

    # CO – Communications: notifications email L1/L2/L3
    notif_count = _count("soc-notifications")
    if notif_count > 20:
        co_score, co_status, co_detail = 100, "ok",  f"{notif_count} notifications email envoyées (L1/L2/L3)"
    elif notif_count > 0:
        co_score, co_status, co_detail = 80,  "ok",  f"{notif_count} notifications envoyées — canaux opérationnels"
    else:
        co_score, co_status, co_detail = 30,  "partial", "Notifier configuré — aucune notification indexée"

    # AN – Analysis: incidents avec analyse automatique (LLM + verdict)
    try:
        llm_count = _count("soc-incidents", {
            "bool": {"should": [
                {"exists": {"field": "ollama_verdict"}},
                {"exists": {"field": "llm_analysis"}},
                {"exists": {"field": "verdict"}}
            ], "minimum_should_match": 1}
        })
    except Exception:
        llm_count = 0
    if llm_count > 20:
        an_score, an_status, an_detail = 100, "ok",  f"{llm_count} incidents analysés automatiquement (LLM + règles)"
    elif llm_count > 0:
        an_score, an_status, an_detail = 80,  "ok",  f"{llm_count} incidents avec analyse LLM/automatique"
    else:
        an_score, an_status, an_detail = 40,  "partial", "Ollama configuré — aucun verdict LLM indexé"

    # MI – Mitigation: blocages actifs + PE events traités
    if blocked_count > 0 and inc_active > 0:
        mi_score, mi_status, mi_detail = 100, "ok",  f"{blocked_count} IPs bloquées + {inc_active} incidents en triage"
    elif blocked_count > 0:
        mi_score, mi_status, mi_detail = 80,  "ok",  f"{blocked_count} IP(s) bloquée(s) via iptables DROP"
    elif inc_active > 0:
        mi_score, mi_status, mi_detail = 60,  "partial", f"{inc_active} incidents en triage — blocage pas encore actif"
    else:
        mi_score, mi_status, mi_detail = 20,  "missing", "Aucune mitigation tracée"

    # IM – Improvements: human feedback loop
    if label_count > 50:
        im_score, im_status, im_detail = 100, "ok",  f"{label_count} labels TP/FP — amélioration continue mature"
    elif label_count > 10:
        im_score, im_status, im_detail = 80,  "ok",  f"{label_count} labels humains — feedback loop actif"
    elif label_count > 0:
        im_score, im_status, im_detail = 50,  "partial", f"{label_count} labels — feedback loop démarré"
    else:
        im_score, im_status, im_detail = 0,   "missing", "Aucun label — feedback loop inactif"

    rs_score = avg_score([rp_score, co_score, an_score, mi_score, im_score])

    # ── RECOVER ───────────────────────────────────────────────────────────────
    # RP – Recovery Planning: incidents clôturés + in_progress
    if closed_inc > 5:
        rc_rp_score, rc_rp_status, rc_rp_detail = 100, "ok",  f"{closed_inc} incidents clôturés — cycle de récupération établi"
    elif closed_inc > 0:
        rc_rp_score, rc_rp_status, rc_rp_detail = 80,  "ok",  f"{closed_inc} incident(s) clôturé(s) — récupération démarrée"
    elif inc_active > 0:
        rc_rp_score, rc_rp_status, rc_rp_detail = 40,  "partial", f"{inc_active} incidents en triage — clôture pas encore faite"
    else:
        rc_rp_score, rc_rp_status, rc_rp_detail = 0,   "missing", "Aucun incident traité — cycle de récupération absent"

    # IM – Post-incident reports
    try:
        report_count = _count("soc-incidents", {"exists": {"field": "post_incident_report"}})
    except Exception:
        report_count = 0
    if report_count > 20:
        rc_im_score, rc_im_status, rc_im_detail = 100, "ok",  f"{report_count} rapports post-incident générés"
    elif report_count > 0:
        rc_im_score, rc_im_status, rc_im_detail = 80,  "ok",  f"{report_count} rapports post-incident disponibles"
    else:
        rc_im_score, rc_im_status, rc_im_detail = 0,   "missing", "Aucun rapport post-incident — POST /api/incidents/<id>/report"

    # CO – Post-incident communications (email + notifications)
    if notif_count > 20:
        rc_co_score, rc_co_status, rc_co_detail = 100, "ok",  f"{notif_count} communications post-incident envoyées"
    elif notif_count > 0:
        rc_co_score, rc_co_status, rc_co_detail = 80,  "ok",  f"{notif_count} notifications — canal de communication actif"
    else:
        rc_co_score, rc_co_status, rc_co_detail = 0,   "missing", "Aucune communication post-incident tracée"

    rc_score = avg_score([rc_rp_score, rc_im_score, rc_co_score])

    return jsonify({
        "functions": [
            {
                "id": "ID", "name": "Identify", "color": "#58a6ff", "score": id_score,
                "items": [
                    {"name": "Gestion des actifs (AM)",    "status": am_status,  "detail": am_detail,  "score": am_score},
                    {"name": "Évaluation des risques (RA)", "status": ra_status,  "detail": ra_detail,  "score": ra_score},
                    {"name": "Threat Intelligence (RA.2)", "status": ra2_status, "detail": ra2_detail, "score": ra2_score},
                    {"name": "Gouvernance (GV)",           "status": gv_status,  "detail": gv_detail,  "score": gv_score},
                ]
            },
            {
                "id": "PR", "name": "Protect", "color": "#3fb950", "score": pr_score,
                "items": [
                    {"name": "Contrôle d'accès (AC)",      "status": ac_status, "detail": ac_detail, "score": ac_score},
                    {"name": "Sécurité des données (DS)",  "status": ds_status, "detail": ds_detail, "score": ds_score},
                    {"name": "Maintenance (MA)",           "status": ma_status, "detail": ma_detail, "score": ma_score},
                    {"name": "Blocage auto (IP)",          "status": ip_status, "detail": ip_detail, "score": ip_score},
                ]
            },
            {
                "id": "DE", "name": "Detect", "color": "#ffa657", "score": de_score,
                "items": [
                    {"name": "Anomalies & Événements (AE)", "status": ae_status, "detail": ae_detail, "score": ae_score},
                    {"name": "Surveillance continue (CM)", "status": cm_status, "detail": cm_detail, "score": cm_score},
                    {"name": "Post-exploitation (DP)",     "status": dp_status, "detail": dp_detail, "score": dp_score},
                    {"name": "ML RandomForest (ML)",       "status": ml_status, "detail": ml_detail, "score": ml_score},
                ]
            },
            {
                "id": "RS", "name": "Respond", "color": "#f85149", "score": rs_score,
                "items": [
                    {"name": "Planification réponse (RP)", "status": rp_status, "detail": rp_detail, "score": rp_score},
                    {"name": "Communications (CO)",        "status": co_status, "detail": co_detail, "score": co_score},
                    {"name": "Analyse LLM (AN)",           "status": an_status, "detail": an_detail, "score": an_score},
                    {"name": "Mitigation (MI)",            "status": mi_status, "detail": mi_detail, "score": mi_score},
                    {"name": "Améliorations (IM)",         "status": im_status, "detail": im_detail, "score": im_score},
                ]
            },
            {
                "id": "RC", "name": "Recover", "color": "#d2a8ff", "score": rc_score,
                "items": [
                    {"name": "Plan de reprise (RP)",       "status": rc_rp_status, "detail": rc_rp_detail, "score": rc_rp_score},
                    {"name": "Rapports post-incident (IM)","status": rc_im_status, "detail": rc_im_detail, "score": rc_im_score},
                    {"name": "Communication (CO)",         "status": rc_co_status, "detail": rc_co_detail, "score": rc_co_score},
                ]
            },
        ]
    })


# ─── BLOCKED IPs LIST ─────────────────────────────────────────────────────────

@app.route("/api/blocked_ips", methods=["GET"])
@require_auth
def api_blocked_ips():
    """Returns all blocked IPs from soc-blocked-ips index."""
    try:
        if not es.indices.exists(index="soc-blocked-ips"):
            return jsonify({"count": 0, "ips": []})
        res = es.search(index="soc-blocked-ips", size=500, sort=[{"@timestamp": {"order": "desc"}}])
        hits = res.get("hits", {}).get("hits", [])
        ips = [{"id": h["_id"], **h["_source"]} for h in hits]
        return jsonify({"count": len(ips), "ips": ips})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── POST-INCIDENT REPORT ─────────────────────────────────────────────────────

@app.route("/api/incidents/<inc_id>/report", methods=["POST"])
@require_level("L2")
def generate_incident_report(inc_id):
    """Generate a structured post-incident report via Ollama llama3. L2+ only."""
    try:
        doc = es.get(index="soc-incidents", id=inc_id)
        src = doc["_source"]

        title         = src.get("title", src.get("alert_type", "Incident réseau"))
        src_ip        = src.get("src_ip", "unknown")
        dst_ip        = src.get("dst_ip", "")
        severity      = src.get("severity", "unknown")
        anomaly_score = src.get("anomaly_score", src.get("unified_score", src.get("score", "N/A")))
        status        = src.get("status", "unknown")
        verdict       = src.get("verdict", "")
        assignee      = src.get("assigned_to", "")
        inc_type      = src.get("type", src.get("attack_type", ""))
        cve_id        = src.get("cve_id", "")
        created_at    = (src.get("created_at") or "")[:16].replace("T", " ")
        closed_at     = (src.get("closed_at")  or "")[:16].replace("T", " ")
        lessons       = src.get("lessons_learned", "")
        llm_verdict   = src.get("llm_verdict", "")
        llm_conf      = src.get("llm_confidence", "")
        llm_attack    = src.get("llm_attack_type", "")
        llm_summary   = src.get("llm_summary", "")
        llm_actions   = src.get("llm_actions", "")

        notes_raw  = src.get("notes", [])
        notes_text = "\n".join(
            f"  [{n.get('timestamp','')[:16]}] {n.get('author','?')}: {n.get('text','')}"
            if isinstance(n, dict) else f"  {n}"
            for n in (notes_raw if isinstance(notes_raw, list) else [])
        ) or "  Aucune note"

        tasks_raw   = src.get("tasks", [])
        done_tasks  = [t for t in tasks_raw if t.get("done")]
        total_tasks = len(tasks_raw)
        tasks_text  = "\n".join(
            f"  [{'x' if t.get('done') else ' '}] {t.get('title','')}"
            for t in tasks_raw
        ) or "  Aucune tache"

        context_parts = [
            f"- Titre: {title}",
            f"- Type: {inc_type}" if inc_type else None,
            f"- IP Source: {src_ip}",
            f"- IP Destination: {dst_ip}" if dst_ip else None,
            f"- Severite: {severity}",
            f"- Score anomalie: {anomaly_score}",
            f"- Statut: {status}",
            f"- Verdict analyste: {verdict}" if verdict else None,
            f"- Assigne a: {assignee}" if assignee else None,
            f"- CVE: {cve_id}" if cve_id else None,
            f"- Ouvert le: {created_at}" if created_at else None,
            f"- Cloture le: {closed_at}" if closed_at else None,
            f"- Analyse IA: {llm_verdict} (confiance {llm_conf}) — {llm_attack}" if llm_verdict else None,
            f"- Resume IA: {llm_summary}" if llm_summary else None,
            f"- Actions recommandees par IA: {llm_actions}" if llm_actions else None,
            f"- Taches: {len(done_tasks)}/{total_tasks} effectuees",
            f"- Notes analyste:\n{notes_text}",
            f"- Lecons apprises: {lessons}" if lessons else None,
        ]
        context_str = "\n".join(p for p in context_parts if p)

        prompt = (
            "Tu es un analyste SOC. Redige un rapport post-incident concis en francais "
            "(200 mots max) avec 4 sections courtes:\n"
            "1) RESUME: ce qui s'est passe (2 phrases)\n"
            "2) TECHNIQUE: vecteur, MITRE ATT&CK\n"
            "3) IMPACT: systemes affectes\n"
            "4) RECOMMANDATIONS: 3 actions prioritaires\n\n"
            f"{context_str}\n\nRapport:"
        )

        ollama_resp = _requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": "gemma2:2b", "prompt": prompt, "stream": False},
            timeout=180
        )
        ollama_resp.raise_for_status()
        report_text = ollama_resp.json().get("response", "").strip()

        if not report_text:
            return jsonify({"error": "Ollama a retourné une réponse vide"}), 500

        src["post_incident_report"] = report_text
        src["report_generated_at"]  = datetime.utcnow().isoformat() + "Z"
        src["updated_at"]           = datetime.utcnow().isoformat() + "Z"
        es.index(index="soc-incidents", id=inc_id, document=src)
        audit_log("generate_report", details={"incident_id": inc_id})

        return jsonify({"report": report_text})
    except _requests.exceptions.Timeout:
        return jsonify({"error": "Ollama timeout (120s) — modèle llama3 disponible ?"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _pdf_safe(text):
    """Remplace les caractères Unicode hors Latin-1 par des équivalents ASCII."""
    if not text:
        return ""
    replacements = {
        "—": "-", "–": "-", "‒": "-",   # tirets longs
        "‘": "'", "’": "'",                   # guillemets simples
        "“": '"', "”": '"',                   # guillemets doubles
        "…": "...",                                # ellipsis
        "•": "-", "‣": "-", "●": "-",   # puces
        "→": "->", "←": "<-",                # flèches
        "·": "-", "‧": "-",                  # points médians
        " ": " ",                                  # espace insécable
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text.encode("latin-1", errors="replace").decode("latin-1")


@app.route("/api/incidents/<inc_id>/report/pdf", methods=["GET"])
@require_level("L2")
def download_incident_report_pdf(inc_id):
    """Télécharge le rapport post-incident en PDF (fpdf2). L2+ only."""
    try:
        from fpdf import FPDF

        doc = es.get(index="soc-incidents", id=inc_id)
        src = doc["_source"]
        report_text = src.get("post_incident_report", "").strip()
        if not report_text:
            return jsonify({"error": "Aucun rapport genere pour cet incident. Generez d'abord le rapport."}), 404

        # ── Extraction des champs ────────────────────────────────
        iid         = _pdf_safe(src.get("incident_id", inc_id[:8].upper()))
        title       = _pdf_safe(src.get("title", "Incident SOC"))
        sev         = _pdf_safe((src.get("severity") or "unknown").upper())
        src_ip      = _pdf_safe(src.get("src_ip", "-"))
        dst_ip      = _pdf_safe(src.get("dst_ip", "-") or "-")
        status      = _pdf_safe(src.get("status", "-"))
        created     = _pdf_safe((src.get("created_at") or "")[:16].replace("T", " ") or "-")
        closed      = _pdf_safe((src.get("closed_at")  or "")[:16].replace("T", " ") or "En cours")
        assignee    = _pdf_safe(src.get("assigned_to", "-") or "-")
        verdict     = _pdf_safe(src.get("verdict", "-") or "-")
        inc_type    = _pdf_safe(src.get("type", src.get("attack_type", "-")) or "-")
        cve_id      = _pdf_safe(src.get("cve_id", "") or "")
        score       = _pdf_safe(str(src.get("unified_score", src.get("anomaly_score", src.get("score", "-"))) or "-"))
        report_at   = _pdf_safe((src.get("report_generated_at") or "")[:16].replace("T", " ") or "-")

        # IA fields
        llm_verdict = _pdf_safe(src.get("llm_verdict", "") or "")
        llm_conf    = src.get("llm_confidence", None)
        llm_conf_s  = _pdf_safe(f"{int(float(llm_conf)*100)}%" if llm_conf is not None else "-")
        llm_attack  = _pdf_safe(src.get("llm_attack_type", "") or "-")
        llm_summary = _pdf_safe(src.get("llm_summary", "") or "")
        llm_actions = _pdf_safe(src.get("llm_actions", "") or "")
        llm_level   = _pdf_safe(src.get("llm_threat_level", "") or "")

        # Notes
        notes_raw = src.get("notes", [])
        notes_list = [
            (
                _pdf_safe((n.get("timestamp","")[:16]).replace("T"," ")),
                _pdf_safe(n.get("author","?")),
                _pdf_safe(n.get("text",""))
            ) if isinstance(n, dict) else ("", "?", _pdf_safe(str(n)))
            for n in (notes_raw if isinstance(notes_raw, list) else [])
        ]

        # Tasks
        tasks_raw   = src.get("tasks", [])
        done_count  = sum(1 for t in tasks_raw if t.get("done"))
        total_count = len(tasks_raw)

        # Lessons learned
        lessons = _pdf_safe(src.get("lessons_learned", "") or "")

        # ── PDF setup ───────────────────────────────────────────
        L, R, T = 18, 18, 18
        pdf = FPDF()
        pdf.set_margins(L, T, R)
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        W   = pdf.w - L - R      # ~174mm
        LBL = 48
        VAL = W - LBL

        def section_title(txt):
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(17, 24, 39)
            pdf.set_fill_color(220, 228, 240)
            pdf.cell(W, 7, _pdf_safe(txt), border=0, ln=True, fill=True)
            pdf.set_draw_color(100, 130, 180)
            pdf.set_line_width(0.4)
            pdf.line(L, pdf.get_y(), L + W, pdf.get_y())
            pdf.ln(2)

        def meta_row(label, value, bold_val=False):
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(230, 232, 236)
            pdf.set_text_color(30, 30, 30)
            pdf.cell(LBL, 6.5, _pdf_safe(label), border=1, fill=True)
            pdf.set_font("Helvetica", "B" if bold_val else "", 8)
            pdf.set_fill_color(248, 249, 250)
            pdf.cell(VAL, 6.5, _pdf_safe(str(value))[:110], border=1, fill=True, ln=True)

        def body_text(txt, indent=0):
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(50, 50, 50)
            if indent:
                pdf.set_x(L + indent)
                pdf.multi_cell(W - indent, 5, _pdf_safe(txt))
            else:
                pdf.multi_cell(W, 5, _pdf_safe(txt))

        # ── Bandeau titre ────────────────────────────────────────
        pdf.set_fill_color(17, 24, 39)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(W, 11, f"RAPPORT POST-INCIDENT  {iid}", border=0, ln=True, fill=True, align="C")
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_fill_color(30, 43, 60)
        pdf.cell(W, 6, f"Mini-SOC Platform  |  Genere le {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC", border=0, ln=True, fill=True, align="C")
        pdf.ln(4)

        # ── 1. Fiche d'identité ──────────────────────────────────
        section_title("1. FICHE D'IDENTITE DE L'INCIDENT")
        meta_row("Identifiant",   iid)
        meta_row("Titre",         title)
        meta_row("Type d'attaque", inc_type)
        meta_row("CVE",           cve_id if cve_id else "-")
        meta_row("Severite",      sev,  bold_val=True)
        meta_row("Score anomalie", score)
        meta_row("IP Source",     src_ip)
        meta_row("IP Destination", dst_ip)
        meta_row("Statut",        status)
        meta_row("Verdict",       verdict, bold_val=True)
        meta_row("Assigne a",     assignee)
        meta_row("Ouvert le",     created)
        meta_row("Cloture le",    closed)
        meta_row("Rapport gen. le", report_at)

        # ── 2. Analyse IA ────────────────────────────────────────
        if llm_verdict:
            section_title("2. ANALYSE IA (LLM)")
            meta_row("Verdict IA",    llm_verdict, bold_val=True)
            meta_row("Confiance",     llm_conf_s)
            meta_row("Type attaque",  llm_attack)
            meta_row("Niveau menace", llm_level if llm_level else "-")
            if llm_summary:
                pdf.ln(2)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(W, 5, "Resume IA:", ln=True)
                body_text(llm_summary, indent=4)
            if llm_actions:
                pdf.ln(1)
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(W, 5, "Actions recommandees par l'IA:", ln=True)
                for action_line in llm_actions.split("\n"):
                    stripped = action_line.strip()
                    if stripped:
                        body_text(f"- {stripped}", indent=4)
        else:
            section_title("2. ANALYSE IA (LLM)")
            body_text("Aucune analyse IA disponible pour cet incident.")

        # ── 3. Rapport d'analyse (Ollama) ────────────────────────
        section_title("3. RAPPORT D'ANALYSE")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(50, 50, 50)
        for line in report_text.split("\n"):
            stripped = _pdf_safe(line.strip())
            if not stripped:
                pdf.ln(2)
                continue
            is_heading = (
                stripped.startswith("#")
                or (len(stripped) > 2 and stripped[0].isdigit() and stripped[1] in ".) ")
                or stripped.upper() == stripped and len(stripped) > 4
            )
            if is_heading:
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(17, 24, 39)
                pdf.multi_cell(W, 6, stripped.lstrip("#").strip())
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(50, 50, 50)
            else:
                pdf.multi_cell(W, 5, stripped)

        # ── 4. Notes de l'analyste ───────────────────────────────
        section_title("4. NOTES DE L'ANALYSTE")
        if notes_list:
            for (ts, author, text) in notes_list:
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(17, 24, 39)
                header_note = f"[{ts}] {author}:" if ts else f"{author}:"
                pdf.cell(W, 5, _pdf_safe(header_note), ln=True)
                body_text(text, indent=6)
                pdf.ln(1)
        else:
            body_text("Aucune note enregistree.")

        # ── 5. Checklist des tâches ──────────────────────────────
        section_title(f"5. CHECKLIST DES TACHES  ({done_count}/{total_count} effectuees)")
        if tasks_raw:
            for t in tasks_raw:
                done   = t.get("done", False)
                tlabel = _pdf_safe(t.get("title", ""))
                mark   = "[X]" if done else "[ ]"
                pdf.set_font("Helvetica", "" if not done else "B", 8)
                pdf.set_text_color(30, 30, 30)
                pdf.cell(W, 5.5, f"  {mark}  {tlabel}", ln=True)
        else:
            body_text("Aucune tache enregistree.")

        # ── 6. Leçons apprises ───────────────────────────────────
        section_title("6. LECONS APPRISES")
        if lessons:
            body_text(lessons)
        else:
            body_text("Aucune lecon apprise documentee.")

        # ── Footer ───────────────────────────────────────────────
        pdf.set_y(-16)
        pdf.set_draw_color(180, 180, 180)
        pdf.set_line_width(0.3)
        pdf.line(L, pdf.get_y(), L + W, pdf.get_y())
        pdf.ln(2)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(W, 4, f"Mini-SOC  |  Rapport {iid}  |  Confidentiel  |  {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC", align="C")

        pdf_bytes = pdf.output()
        audit_log("download_report_pdf", details={"incident_id": iid})
        resp = make_response(bytes(pdf_bytes))
        resp.headers["Content-Type"]        = "application/pdf"
        resp.headers["Content-Disposition"] = f'attachment; filename="rapport_{iid}.pdf"'
        return resp
    except ImportError:
        return jsonify({"error": "fpdf2 non installe — pip install fpdf2"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/postexploit/latest")
@require_level("L2")
def api_postexploit_latest():
    """Dernier événement post-exploit (pour le toast temps réel)."""
    try:
        since = request.args.get("since", "now-2m")
        r = es.search(
            index="soc-postexploit-events", size=1,
            query={"range": {"detected_at": {"gte": since}}},
            sort=[{"detected_at": {"order": "desc"}}],
            _source=["detected_at", "src_ip", "technique", "tactic", "severity", "description", "matched"]
        )
        hits = r["hits"]["hits"]
        if not hits:
            return jsonify({"event": None})
        s = hits[0]["_source"]
        return jsonify({"event": {
            "detected_at": s.get("detected_at", ""),
            "src_ip":      s.get("src_ip", ""),
            "technique":   s.get("technique", ""),
            "tactic":      s.get("tactic", ""),
            "severity":    s.get("severity", ""),
            "description": s.get("description", ""),
            "matched":     s.get("matched", ""),
        }})
    except Exception as e:
        return jsonify({"event": None, "error": str(e)})


@app.route("/api/postexploit/ip_incidents/<path:ip>")
@require_level("L2")
def api_postexploit_ip_incidents(ip):
    """Incidents liés à une IP spécifique, triés par date desc."""
    try:
        r = es.search(
            index="soc-incidents", size=20,
            query={"term": {"src_ip": ip}},
            sort=[{"created_at": {"order": "desc"}}],
            _source=["created_at", "title", "severity", "status", "anomaly_score",
                     "src_ip", "log_type", "ssh_user"]
        )
        incidents = []
        for h in r["hits"]["hits"]:
            s = h["_source"]
            s["id"] = h["_id"]
            incidents.append(s)
        return jsonify({"incidents": incidents, "total": r["hits"]["total"]["value"]})
    except Exception as e:
        return jsonify({"incidents": [], "total": 0, "error": str(e)})


@app.route("/api/postexploit/ip_logs/<path:ip>")
@require_level("L2")
def api_postexploit_ip_logs(ip):
    """Logs bruts liés à une IP — auth + syslog, 72h glissantes."""
    try:
        window = request.args.get("window", "now-72h")
        r = es.search(
            index="soc-logs*", size=100,
            query={"bool": {"must": [
                {"range": {"@timestamp": {"gte": window}}},
            ], "should": [
                {"term": {"src_ip": ip}},
                {"match_phrase": {"message": ip}},
            ], "minimum_should_match": 1}},
            sort=[{"@timestamp": {"order": "desc"}}],
            _source=["@timestamp", "message", "program", "log_type", "src_ip", "hostname"]
        )
        logs = [h["_source"] for h in r["hits"]["hits"]]
        return jsonify({"logs": logs, "total": r["hits"]["total"]["value"]})
    except Exception as e:
        return jsonify({"logs": [], "total": 0, "error": str(e)})


@app.route("/api/bot/chat", methods=["POST"])
@require_auth
def api_bot_chat():
    """SOC Bot conversationnel — Ollama gemma2:2b streaming SSE."""
    import json as _json
    data    = request.get_json(force=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "no message"}), 400

    # ── Collecter le contexte SOC en temps réel ──────────────────────────
    try:
        inc_open = es.count(index="soc-incidents",
            query={"terms": {"status": ["open", "awaiting_action", "in_progress"]}})["count"]
    except Exception:
        inc_open = 0
    try:
        inc_critical = es.count(index="soc-incidents",
            query={"bool": {"must": [
                {"term": {"severity": "critical"}},
                {"terms": {"status": ["open", "awaiting_action"]}}
            ]}})["count"]
    except Exception:
        inc_critical = 0
    try:
        anomalies_24h = es.count(index="soc-anomalies",
            query={"range": {"@timestamp": {"gte": "now-24h"}}})["count"]
    except Exception:
        anomalies_24h = 0
    try:
        pe_events = es.count(index="soc-postexploit-events",
            query={"range": {"@timestamp": {"gte": "now-24h"}}})["count"]
    except Exception:
        pe_events = 0
    try:
        r_pe = es.search(index="soc-postexploit-events", size=2,
            sort=[{"detected_at": {"order": "desc"}}],
            _source=["src_ip", "technique", "tactic", "severity", "detected_at"])
        recent_pe = [h["_source"] for h in r_pe["hits"]["hits"]]
    except Exception:
        recent_pe = []
    try:
        r_inc = es.search(index="soc-incidents", size=2,
            query={"terms": {"status": ["open", "awaiting_action"]}},
            sort=[{"created_at": {"order": "desc"}}],
            _source=["title", "src_ip", "severity"])
        recent_inc = [h["_source"] for h in r_inc["hits"]["hits"]]
    except Exception:
        recent_inc = []
    try:
        blocked_count = es.count(index="soc-blocked-ips")["count"] if \
            es.indices.exists(index="soc-blocked-ips") else 0
    except Exception:
        blocked_count = 0

    # ── Prompt compact ───────────────────────────────────────────────────
    pe_lines = " | ".join(
        f"{e.get('src_ip','?')} {e.get('technique','')} ({e.get('severity','')})"
        for e in recent_pe
    ) or "aucun"
    inc_lines = " | ".join(
        f"{i.get('title','')[:40]} [{i.get('severity','')}]"
        for i in recent_inc
    ) or "aucun"

    system_prompt = (
        f"Tu es SOC Bot, assistant sécurité du Mini-SOC. Réponds en français, "
        f"concis (max 5 phrases). Expert MITRE ATT&CK, NIST CSF, incidents.\n"
        f"SOC: {inc_open} incidents ({inc_critical} critiques), "
        f"{anomalies_24h} anomalies 24h, {pe_events} post-exploit 24h, {blocked_count} IPs bloquées.\n"
        f"Derniers PE: {pe_lines}\n"
        f"Derniers incidents: {inc_lines}\n"
        f"Si commandes, utilise blocs markdown."
    )
    full_prompt = f"{system_prompt}\n\nAnalyste: {message}\nSOC Bot:"

    # ── Stream SSE vers le client ────────────────────────────────────────
    import threading as _threading
    import queue as _queue
    captured_prompt = full_prompt  # capture before leaving request context

    def generate_sse():
        yield ": connected\n\n"

        q = _queue.Queue()

        def _run_ollama():
            try:
                resp = _requests.post(
                    f"{OLLAMA_URL}/api/generate",
                    json={"model": "gemma2:2b", "prompt": captured_prompt, "stream": True,
                          "options": {"temperature": 0.4, "num_predict": 400}},
                    stream=True, timeout=(15, 300)
                )
                for raw in resp.iter_lines():
                    if not raw:
                        continue
                    chunk = _json.loads(raw)
                    token = chunk.get("response", "")
                    if token:
                        q.put(("token", token))
                    if chunk.get("done"):
                        break
            except Exception as exc:
                err_str = str(exc)
                if "Connection refused" in err_str or "Max retries" in err_str or "NewConnectionError" in err_str:
                    q.put(("error", "Le service Ollama n'est pas disponible (port 11434). Lancez : sudo systemctl start ollama"))
                else:
                    q.put(("error", f"Erreur LLM : {err_str[:120]}"))
            q.put(("done", None))

        _threading.Thread(target=_run_ollama, daemon=True).start()

        while True:
            try:
                kind, data = q.get(timeout=5)
                if kind == "token":
                    yield f"data: {_json.dumps({'token': data})}\n\n"
                elif kind == "error":
                    yield f"data: {_json.dumps({'error': data})}\n\n"
                    break
                else:
                    break
            except _queue.Empty:
                yield ": ping\n\n"  # keep connection alive on slow CPU
        yield "data: [DONE]\n\n"

    return Response(
        generate_sse(),
        mimetype="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache",
                 "Connection": "keep-alive"}
    )


# ─── THREAT HUNTING ──────────────────────────────────────────────────────────

@app.route("/hunting")
@require_level("L2")
def hunting_page():
    """Page de threat hunting libre — L2+ only."""
    indices = []
    try:
        cat = es.cat.indices(format="json", h="index,docs.count,store.size")
        indices = sorted(
            [i for i in cat if not i["index"].startswith(".")],
            key=lambda x: x["index"]
        )
    except Exception:
        pass
    return render_template("hunting.html", indices=indices, current_user=get_current_user())


@app.route("/api/hunting/query", methods=["POST"])
@require_level("L2")
def api_hunting_query():
    """Exécute une requête ES libre depuis la page threat hunting."""
    data  = request.get_json(force=True) or {}
    index = data.get("index", "soc-logs*")
    size  = min(500, max(1, int(data.get("size", 50))))
    try:
        raw_query = data.get("query") or {}
        if isinstance(raw_query, str):
            import json as _json2
            raw_query = _json2.loads(raw_query)
    except Exception as e:
        return jsonify({"error": f"JSON invalide: {e}"}), 400

    try:
        r = es.search(index=index, query=raw_query or {"match_all": {}},
                      size=size, sort=[{"@timestamp": {"order": "desc"}}])
        hits = [{"_id": h["_id"], "_index": h["_index"],
                 "_score": h.get("_score"), **h["_source"]} for h in r["hits"]["hits"]]
        audit_log("hunting_query", username=session.get("username"),
                  details={"index": index, "hits": len(hits)})
        return jsonify({"total": r["hits"]["total"]["value"], "hits": hits})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── INTERACTIVE TIMELINE PER IP ─────────────────────────────────────────────

@app.route("/api/timeline/<path:ip>")
@require_auth
def api_ip_timeline(ip):
    """Retourne la timeline complète d'une IP : logs → anomalies → PE → blocage."""
    try:
        events = []
        ip_filter = {"term": {"src_ip": ip}}

        # Auth/Apache logs
        try:
            r = es.search(index="soc-logs*", query=ip_filter, size=30,
                          sort=[{"@timestamp": {"order": "asc"}}],
                          _source=["@timestamp", "message", "log_type", "severity", "tags"])
            for h in r["hits"]["hits"]:
                s = h["_source"]
                events.append({"ts": s.get("@timestamp", ""), "kind": "log",
                               "icon": "fa-file-alt", "color": "var(--muted)",
                               "label": s.get("log_type", "log"),
                               "detail": (s.get("message") or "")[:120],
                               "sev": s.get("severity", "info")})
        except Exception:
            pass

        # Anomalies
        try:
            r = es.search(index="soc-anomalies", query=ip_filter, size=10,
                          sort=[{"@timestamp": {"order": "asc"}}],
                          _source=["@timestamp", "score", "alert_type", "unified_score"])
            for h in r["hits"]["hits"]:
                s = h["_source"]
                events.append({"ts": s.get("@timestamp", ""), "kind": "anomaly",
                               "icon": "fa-brain", "color": "var(--purple)",
                               "label": f"Anomalie IA — score {s.get('unified_score') or s.get('score','?')}",
                               "detail": s.get("alert_type", ""),
                               "sev": "high"})
        except Exception:
            pass

        # Post-exploit events
        try:
            r = es.search(index="soc-postexploit-events", query=ip_filter, size=10,
                          sort=[{"detected_at": {"order": "asc"}}],
                          _source=["detected_at", "technique", "tactic", "severity"])
            for h in r["hits"]["hits"]:
                s = h["_source"]
                events.append({"ts": s.get("detected_at", ""), "kind": "postexploit",
                               "icon": "fa-skull-crossbones", "color": "var(--red)",
                               "label": f"Post-exploit: {s.get('technique','')}",
                               "detail": s.get("tactic", ""),
                               "sev": s.get("severity", "critical")})
        except Exception:
            pass

        # Incidents
        try:
            r = es.search(index="soc-incidents", query=ip_filter, size=5,
                          sort=[{"created_at": {"order": "asc"}}],
                          _source=["created_at", "title", "severity", "status", "incident_id"])
            for h in r["hits"]["hits"]:
                s = h["_source"]
                events.append({"ts": s.get("created_at", ""), "kind": "incident",
                               "icon": "fa-ticket-alt", "color": "var(--orange)",
                               "label": f"Incident {s.get('incident_id','')} — {s.get('status','')}",
                               "detail": s.get("title", ""),
                               "sev": s.get("severity", "medium")})
        except Exception:
            pass

        # Blocked
        try:
            r = es.search(index="soc-blocked-ips", query={"term": {"ip": ip}}, size=5,
                          _source=["@timestamp", "reason", "blocked_by"])
            for h in r["hits"]["hits"]:
                s = h["_source"]
                events.append({"ts": s.get("@timestamp", ""), "kind": "block",
                               "icon": "fa-ban", "color": "var(--green)",
                               "label": "IP bloquée (iptables DROP)",
                               "detail": f"Par {s.get('blocked_by','?')} — {s.get('reason','')}",
                               "sev": "info"})
        except Exception:
            pass

        events.sort(key=lambda e: e["ts"])
        return jsonify({"ip": ip, "count": len(events), "events": events})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── DYNAMIC RISK SCORE PER IP ───────────────────────────────────────────────

@app.route("/api/postexploit/risk_scores")
@require_level("L2")
def api_risk_scores():
    """Calcule un score de risque dynamique par IP (anomalies + PE + incidents + blocage)."""
    try:
        scores = {}

        def _add(ip, category, weight):
            if not ip: return
            if ip not in scores:
                scores[ip] = {"ip": ip, "score": 0, "anomalies": 0, "pe_events": 0,
                              "incidents": 0, "blocked": False, "last_seen": ""}
            scores[ip]["score"] += weight
            scores[ip][category] = scores[ip].get(category, 0) + 1

        # PE events (weight 40)
        try:
            r = es.search(index="soc-postexploit-events", size=500,
                          sort=[{"detected_at": {"order": "desc"}}],
                          _source=["src_ip", "detected_at", "severity"])
            for h in r["hits"]["hits"]:
                s = h["_source"]
                ip  = s.get("src_ip", "")
                w   = 50 if s.get("severity") == "critical" else 40
                _add(ip, "pe_events", w)
                if ip in scores and s.get("detected_at", "") > scores[ip]["last_seen"]:
                    scores[ip]["last_seen"] = s.get("detected_at", "")
        except Exception: pass

        # Anomalies (weight 25)
        try:
            r = es.search(index="soc-anomalies", size=500,
                          sort=[{"@timestamp": {"order": "desc"}}],
                          _source=["src_ip", "@timestamp"])
            for h in r["hits"]["hits"]:
                s = h["_source"]
                _add(s.get("src_ip",""), "anomalies", 25)
        except Exception: pass

        # Incidents (weight 30)
        try:
            r = es.search(index="soc-incidents", size=200,
                          _source=["src_ip", "severity", "status"])
            for h in r["hits"]["hits"]:
                s = h["_source"]
                if not s.get("src_ip"): continue
                w = 35 if s.get("severity") in ("critical","high") else 20
                _add(s.get("src_ip",""), "incidents", w)
        except Exception: pass

        # Blocked (cap score to max 100 or boost)
        try:
            r = es.search(index="soc-blocked-ips", size=200, _source=["ip"])
            for h in r["hits"]["hits"]:
                ip = h["_source"].get("ip","")
                if ip in scores:
                    scores[ip]["blocked"] = True
        except Exception: pass

        # Normalize score 0-100
        result = sorted(scores.values(), key=lambda x: x["score"], reverse=True)[:50]
        max_raw = result[0]["score"] if result else 1
        for r2 in result:
            r2["score_pct"] = min(100, round(r2["score"] / max_raw * 100))
        return jsonify({"count": len(result), "scores": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── FILEBEAT HEALTH CHECK ───────────────────────────────────────────────────

@app.route("/api/health/filebeat")
@require_auth
def api_health_filebeat():
    """Vérifie si Filebeat envoie des logs (dernières 5 minutes)."""
    try:
        r = es.count(index="soc-logs*",
                     query={"range": {"@timestamp": {"gte": "now-5m"}}})
        count = r["count"]
        status = "ok" if count > 0 else "down"
        return jsonify({
            "status": status,
            "logs_last_5min": count,
            "message": f"{count} logs reçus dans les 5 dernières minutes" if count > 0
                       else "⚠ Aucun log reçu depuis 5 minutes — Filebeat down ?"
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


# ─── SOAR AUTO-RESPONSE ──────────────────────────────────────────────────────

def soar_auto_analyze(inc_id: str, incident_doc: dict):
    """SOAR : analyse Ollama auto + notification bot pour incidents critiques."""
    import threading as _t2
    def _run():
        try:
            src_ip   = incident_doc.get("src_ip", "unknown")
            title    = incident_doc.get("title", "Incident")
            severity = incident_doc.get("severity", "high")
            notes    = "; ".join(
                n["text"] if isinstance(n, dict) else str(n)
                for n in (incident_doc.get("notes", []) or [])
            ) or "Aucune note"

            prompt = (
                f"Incident SOC critique. Analyse rapide en 3 phrases max (français):\n"
                f"- Titre: {title}\n- IP: {src_ip}\n- Sévérité: {severity}\n- Notes: {notes}\n"
                f"Verdict probable (true_positive/false_positive) et action immédiate recommandée."
            )
            resp = _requests.post(f"{OLLAMA_URL}/api/generate",
                json={"model": "gemma2:2b", "prompt": prompt, "stream": False,
                      "options": {"temperature": 0.3, "num_predict": 150}},
                timeout=180)
            analysis = resp.json().get("response", "").strip()
            if analysis:
                # Save to incident
                doc = es.get(index="soc-incidents", id=inc_id)
                src = doc["_source"]
                src["soar_analysis"]    = analysis
                src["soar_analyzed_at"] = datetime.now(timezone.utc).isoformat()
                es.index(index="soc-incidents", id=inc_id, document=src)

                # Push notification to all L2/L3
                try:
                    users_data = _load_users()
                    for u in users_data.values():
                        if u.get("level") in ("L2", "L3"):
                            push_notif(u["name"],
                                f"🤖 SOAR analyse {incident_doc.get('incident_id',inc_id[:8].upper())}: {analysis[:100]}…",
                                notif_type="warning", incident_id=inc_id,
                                severity=severity)
                except Exception: pass
                audit_log("soar_auto_analysis", details={"incident_id": inc_id, "model": "gemma2:2b"})
        except Exception as e:
            log.error(f"SOAR auto-analysis failed for {inc_id}: {e}")
    _t2.Thread(target=_run, daemon=True).start()


# ─── FIELD ENCRYPTION (Fernet) ───────────────────────────────────────────────

def _get_fernet():
    """Returns a Fernet instance using FERNET_KEY from env, or None if not configured."""
    key = os.environ.get("FERNET_KEY", "")
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        return None

def encrypt_field(value: str) -> str:
    """Encrypts a string field. Returns original if Fernet not configured."""
    f = _get_fernet()
    if not f or not value:
        return value
    return f.encrypt(value.encode()).decode()

def decrypt_field(token: str) -> str:
    """Decrypts a Fernet-encrypted field. Returns original on error."""
    f = _get_fernet()
    if not f or not token:
        return token
    try:
        return f.decrypt(token.encode()).decode()
    except Exception:
        return token

@app.route("/api/admin/generate_fernet_key", methods=["POST"])
@require_level("L3")
def api_generate_fernet_key():
    """Génère une nouvelle clé Fernet pour chiffrement des champs sensibles."""
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode()
    audit_log("generate_fernet_key", username=session.get("username"))
    return jsonify({"key": key,
                    "instructions": "Ajoutez FERNET_KEY=<key> dans votre fichier .env"})


# ─── SHIFTS / MULTI-TENANT ───────────────────────────────────────────────────

_SHIFTS_FILE = os.path.join(os.path.dirname(__file__), "shifts.json")

def _load_shifts():
    try:
        with open(_SHIFTS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"shifts": [], "history": []}

def _save_shifts(data):
    with open(_SHIFTS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def _current_shift(shifts):
    """Returns the shift currently active based on time-of-day."""
    from datetime import time as _time
    now_t = datetime.now().strftime("%H:%M")
    for s in shifts:
        start = s.get("start", "00:00")
        end   = s.get("end",   "00:00")
        if start < end:
            if start <= now_t < end:
                return s
        else:  # crosses midnight
            if now_t >= start or now_t < end:
                return s
    return shifts[0] if shifts else None


@app.route("/admin/shifts")
@require_level("L3")
def admin_shifts_page():
    data  = _load_shifts()
    users = _load_users()
    return render_template("admin_shifts.html",
                           shifts=data["shifts"],
                           history=data.get("history", [])[-20:],
                           current_shift=_current_shift(data["shifts"]),
                           users=list(users.values()),
                           current_user=get_current_user())


@app.route("/api/shifts", methods=["GET"])
@require_auth
def api_shifts_get():
    data = _load_shifts()
    cur  = _current_shift(data["shifts"])
    return jsonify({"shifts": data["shifts"], "current": cur,
                    "history": data.get("history", [])[-10:]})


@app.route("/api/shifts", methods=["POST"])
@require_level("L3")
def api_shifts_create():
    body = request.get_json(force=True) or {}
    name = body.get("name", "").strip()
    if not name:
        return jsonify({"error": "name requis"}), 400
    data = _load_shifts()
    if any(s["name"] == name for s in data["shifts"]):
        return jsonify({"error": "Shift déjà existant"}), 409
    shift = {
        "name":        name,
        "color":       body.get("color", "blue"),
        "icon":        body.get("icon", "fa-clock"),
        "start":       body.get("start", "00:00"),
        "end":         body.get("end",   "08:00"),
        "members":     body.get("members", []),
        "description": body.get("description", ""),
    }
    data["shifts"].append(shift)
    _save_shifts(data)
    audit_log("shift_created", username=session.get("username"), details={"shift": name})
    return jsonify({"status": "ok", "shift": shift})


@app.route("/api/shifts/<shift_name>", methods=["PUT"])
@require_level("L3")
def api_shifts_update(shift_name):
    body  = request.get_json(force=True) or {}
    data  = _load_shifts()
    shift = next((s for s in data["shifts"] if s["name"] == shift_name), None)
    if not shift:
        return jsonify({"error": "Shift non trouvé"}), 404
    for key in ("color", "icon", "start", "end", "members", "description"):
        if key in body:
            shift[key] = body[key]
    _save_shifts(data)
    audit_log("shift_updated", username=session.get("username"), details={"shift": shift_name})
    return jsonify({"status": "ok", "shift": shift})


@app.route("/api/shifts/<shift_name>/assign", methods=["POST"])
@require_level("L2")
def api_shifts_assign(shift_name):
    """Assigner ou retirer un analyste d'un shift."""
    body     = request.get_json(force=True) or {}
    username = body.get("username", "").strip()
    action   = body.get("action", "add")  # add | remove
    if not username:
        return jsonify({"error": "username requis"}), 400
    data  = _load_shifts()
    shift = next((s for s in data["shifts"] if s["name"] == shift_name), None)
    if not shift:
        return jsonify({"error": "Shift non trouvé"}), 404
    members = shift.setdefault("members", [])
    if action == "add" and username not in members:
        members.append(username)
        # Remove from other shifts
        for s in data["shifts"]:
            if s["name"] != shift_name and username in s.get("members", []):
                s["members"].remove(username)
    elif action == "remove" and username in members:
        members.remove(username)
    now = datetime.now(timezone.utc).isoformat()
    data.setdefault("history", []).append({
        "ts": now, "shift": shift_name, "action": action,
        "username": username, "by": session.get("username", "?")
    })
    _save_shifts(data)
    audit_log(f"shift_{action}", username=session.get("username"),
              details={"shift": shift_name, "target": username})
    return jsonify({"status": "ok", "members": members})


@app.route("/api/shifts/<shift_name>", methods=["DELETE"])
@require_level("L3")
def api_shifts_delete(shift_name):
    data = _load_shifts()
    before = len(data["shifts"])
    data["shifts"] = [s for s in data["shifts"] if s["name"] != shift_name]
    if len(data["shifts"]) == before:
        return jsonify({"error": "Shift non trouvé"}), 404
    _save_shifts(data)
    audit_log("shift_deleted", username=session.get("username"), details={"shift": shift_name})
    return jsonify({"status": "ok"})


@app.route("/api/shifts/current")
@require_auth
def api_current_shift():
    data = _load_shifts()
    cur  = _current_shift(data["shifts"])
    return jsonify({"current": cur})


@app.route("/correlation")
@require_level("L1")
def correlation_page():
    """Page de corrélation multi-événements — L1+ only."""
    return render_template("correlation.html")


@app.route("/api/correlation/groups")
@require_level("L1")
def api_correlation_groups():
    """
    Groupe les incidents + anomalies par IP source.
    Retourne pour chaque IP: nb incidents, nb anomalies, sévérité max,
    dernière activité, verdict IA majoritaire, attack_type, score max.
    """
    try:
        hours = int(request.args.get("hours", 168))  # 7 jours par défaut
        since = f"now-{hours}h"

        # ── Incidents par IP ─────────────────────────────────────
        inc_agg = es.search(
            index="soc-incidents", size=0,
            query={"range": {"created_at": {"gte": since}}},
            aggs={
                "by_ip": {
                    "terms": {"field": "src_ip.keyword", "size": 200, "min_doc_count": 1},
                    "aggs": {
                        "max_score":     {"max":        {"field": "unified_score"}},
                        "last_seen":     {"max":        {"field": "created_at"}},
                        "severities":    {"terms":      {"field": "severity.keyword", "size": 5}},
                        "attack_types":  {"terms":      {"field": "llm_attack_type.keyword", "size": 5}},
                        "verdicts":      {"terms":      {"field": "llm_verdict.keyword",    "size": 5}},
                        "statuses":      {"terms":      {"field": "status.keyword",         "size": 5}},
                        "sample":        {"top_hits":   {"size": 1, "_source": ["title","assigned_to","verdict","severity","status","created_at","llm_attack_type","llm_verdict"]}},
                    }
                }
            }
        )

        # ── Anomalies ensemble par IP ─────────────────────────────
        anom_agg = es.search(
            index="soc-anomalies,soc-dl-anomalies,soc-rf-anomalies", size=0,
            ignore_unavailable=True,
            query={"range": {"@timestamp": {"gte": since}}},
            aggs={
                "by_ip": {
                    "terms": {"field": "src_ip.keyword", "size": 200},
                    "aggs": {
                        "max_score": {"max": {"field": "anomaly_score"}},
                        "last_seen": {"max": {"field": "@timestamp"}},
                    }
                }
            }
        )

        # ── Logs bruts par IP ─────────────────────────────────────
        log_agg = es.search(
            index="soc-logs*", size=0,
            ignore_unavailable=True,
            query={"range": {"@timestamp": {"gte": since}}},
            aggs={
                "by_ip": {
                    "terms": {"field": "src_ip.keyword", "size": 200},
                    "aggs": {
                        "last_seen":  {"max":   {"field": "@timestamp"}},
                        "log_types":  {"terms": {"field": "log_type.keyword", "size": 5}},
                        "severities": {"terms": {"field": "severity.keyword", "size": 5}},
                    }
                }
            }
        )

        # ── Merge par IP ──────────────────────────────────────────
        groups = {}

        for bkt in inc_agg["aggregations"]["by_ip"]["buckets"]:
            ip = bkt["key"]
            sample_src = bkt["sample"]["hits"]["hits"][0]["_source"] if bkt["sample"]["hits"]["hits"] else {}
            top_sev  = bkt["severities"]["buckets"][0]["key"] if bkt["severities"]["buckets"] else "unknown"
            top_atk  = bkt["attack_types"]["buckets"][0]["key"] if bkt["attack_types"]["buckets"] else ""
            top_vrd  = bkt["verdicts"]["buckets"][0]["key"] if bkt["verdicts"]["buckets"] else ""
            top_stat = bkt["statuses"]["buckets"][0]["key"] if bkt["statuses"]["buckets"] else ""
            groups[ip] = {
                "ip":            ip,
                "incident_count": bkt["doc_count"],
                "anomaly_count":  0,
                "log_count":      0,
                "max_score":      round(bkt["max_score"]["value"] or 0, 3),
                "last_seen":      (bkt["last_seen"]["value_as_string"] or "")[:16].replace("T", " "),
                "top_severity":   top_sev,
                "top_attack":     top_atk,
                "top_verdict":    top_vrd,
                "top_status":     top_stat,
                "assignee":       sample_src.get("assigned_to", ""),
                "log_types":      [],
            }

        for bkt in anom_agg["aggregations"]["by_ip"]["buckets"]:
            ip = bkt["key"]
            sc = round(bkt["max_score"]["value"] or 0, 3)
            if ip in groups:
                groups[ip]["anomaly_count"] = bkt["doc_count"]
                if sc > groups[ip]["max_score"]:
                    groups[ip]["max_score"] = sc
            else:
                groups[ip] = {
                    "ip": ip, "incident_count": 0,
                    "anomaly_count": bkt["doc_count"], "log_count": 0,
                    "max_score": sc,
                    "last_seen": (bkt["last_seen"]["value_as_string"] or "")[:16].replace("T", " "),
                    "top_severity": "unknown", "top_attack": "", "top_verdict": "",
                    "top_status": "", "assignee": "", "log_types": [],
                }

        for bkt in log_agg["aggregations"]["by_ip"]["buckets"]:
            ip = bkt["key"]
            ltypes = [b["key"] for b in bkt["log_types"]["buckets"]]
            if ip in groups:
                groups[ip]["log_count"] = bkt["doc_count"]
                groups[ip]["log_types"] = ltypes
            else:
                groups[ip] = {
                    "ip": ip, "incident_count": 0, "anomaly_count": 0,
                    "log_count": bkt["doc_count"], "max_score": 0,
                    "last_seen": (bkt["last_seen"]["value_as_string"] or "")[:16].replace("T", " "),
                    "top_severity": "unknown", "top_attack": "", "top_verdict": "",
                    "top_status": "", "assignee": "", "log_types": ltypes,
                }

        # Trier : incidents desc, puis anomalies, puis logs
        result = sorted(
            groups.values(),
            key=lambda g: (g["incident_count"], g["anomaly_count"], g["max_score"]),
            reverse=True
        )
        return jsonify({"groups": result, "total": len(result), "window_hours": hours})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/correlation/ip/<path:ip>")
@require_level("L1")
def api_correlation_ip(ip):
    """
    Timeline complète d'une IP : logs + anomalies + incidents.
    Utilisé pour le panneau de détail dans la page corrélation.
    """
    try:
        hours = int(request.args.get("hours", 168))
        since = f"now-{hours}h"

        # Incidents
        inc_res = es.search(
            index="soc-incidents", size=50,
            query={"bool": {"must": [
                {"term":  {"src_ip.keyword": ip}},
                {"range": {"created_at": {"gte": since}}}
            ]}},
            sort=[{"created_at": {"order": "desc"}}],
            _source=["incident_id","title","severity","status","verdict","created_at",
                     "closed_at","assigned_to","llm_verdict","llm_attack_type","llm_confidence","unified_score"]
        )
        incidents = [{"_id": h["_id"], **h["_source"]} for h in inc_res["hits"]["hits"]]

        # Anomalies (all models)
        try:
            anom_res = es.search(
                index="soc-anomalies,soc-dl-anomalies,soc-rf-anomalies",
                ignore_unavailable=True, size=50,
                query={"bool": {"must": [
                    {"term":  {"src_ip.keyword": ip}},
                    {"range": {"@timestamp": {"gte": since}}}
                ]}},
                sort=[{"@timestamp": {"order": "desc"}}],
                _source=["@timestamp","anomaly_score","severity","model","log_type","message"]
            )
            anomalies = [h["_source"] for h in anom_res["hits"]["hits"]]
        except Exception:
            anomalies = []

        # Logs bruts récents (50 max)
        try:
            log_res = es.search(
                index="soc-logs*", ignore_unavailable=True, size=50,
                query={"bool": {"must": [
                    {"term":  {"src_ip.keyword": ip}},
                    {"range": {"@timestamp": {"gte": since}}}
                ]}},
                sort=[{"@timestamp": {"order": "desc"}}],
                _source=["@timestamp","log_type","severity","message","hostname","ssh_user","status_code"]
            )
            logs = [h["_source"] for h in log_res["hits"]["hits"]]
        except Exception:
            logs = []

        # Timeline horaire (log_count par heure sur 7j)
        try:
            tl_res = es.search(
                index="soc-logs*", ignore_unavailable=True, size=0,
                query={"bool": {"must": [
                    {"term":  {"src_ip.keyword": ip}},
                    {"range": {"@timestamp": {"gte": since}}}
                ]}},
                aggs={"hourly": {"date_histogram": {
                    "field": "@timestamp", "calendar_interval": "hour",
                    "min_doc_count": 1
                }}}
            )
            timeline = [
                {"ts": b["key_as_string"][:13], "count": b["doc_count"]}
                for b in tl_res["aggregations"]["hourly"]["buckets"]
            ]
        except Exception:
            timeline = []

        return jsonify({
            "ip": ip, "incidents": incidents,
            "anomalies": anomalies, "logs": logs,
            "timeline": timeline,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/correlation/campaigns")
@require_level("L1")
def api_correlation_campaigns():
    """
    Groupe les incidents par attack_type (campagne d'attaque).
    Retourne les top campagnes avec IPs impliquées, fenêtre temporelle, nb incidents.
    """
    try:
        hours = int(request.args.get("hours", 168))
        since = f"now-{hours}h"

        res = es.search(
            index="soc-incidents", size=0,
            query={"range": {"created_at": {"gte": since}}},
            aggs={
                "by_attack": {
                    "terms": {"field": "llm_attack_type.keyword", "size": 30, "min_doc_count": 2},
                    "aggs": {
                        "ips":        {"terms": {"field": "src_ip.keyword",  "size": 20}},
                        "severities": {"terms": {"field": "severity.keyword", "size": 5}},
                        "first_seen": {"min":   {"field": "created_at"}},
                        "last_seen":  {"max":   {"field": "created_at"}},
                        "max_score":  {"max":   {"field": "unified_score"}},
                        "verdicts":   {"terms": {"field": "llm_verdict.keyword", "size": 3}},
                    }
                }
            }
        )

        campaigns = []
        for bkt in res["aggregations"]["by_attack"]["buckets"]:
            top_sev = bkt["severities"]["buckets"][0]["key"] if bkt["severities"]["buckets"] else "unknown"
            campaigns.append({
                "attack_type":     bkt["key"],
                "incident_count":  bkt["doc_count"],
                "unique_ips":      len(bkt["ips"]["buckets"]),
                "ips":             [b["key"] for b in bkt["ips"]["buckets"][:10]],
                "top_severity":    top_sev,
                "max_score":       round(bkt["max_score"]["value"] or 0, 3),
                "first_seen":      (bkt["first_seen"]["value_as_string"] or "")[:16].replace("T"," "),
                "last_seen":       (bkt["last_seen"]["value_as_string"]  or "")[:16].replace("T"," "),
                "verdicts":        {b["key"]: b["doc_count"] for b in bkt["verdicts"]["buckets"]},
            })

        campaigns.sort(key=lambda c: c["incident_count"], reverse=True)
        return jsonify({"campaigns": campaigns, "window_hours": hours})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/correlation/heatmap")
@require_level("L1")
def api_correlation_heatmap():
    """
    Heatmap activité : bucket par heure × sévérité sur les logs bruts.
    Pour le graphique calendrier/heatmap dans la page corrélation.
    """
    try:
        hours = int(request.args.get("hours", 72))
        since = f"now-{hours}h"

        res = es.search(
            index="soc-logs*", ignore_unavailable=True, size=0,
            query={"range": {"@timestamp": {"gte": since}}},
            aggs={
                "hourly": {
                    "date_histogram": {
                        "field": "@timestamp", "calendar_interval": "hour",
                        "min_doc_count": 0,
                        "extended_bounds": {"min": f"now-{hours}h", "max": "now"}
                    },
                    "aggs": {
                        "by_sev": {"terms": {"field": "severity.keyword", "size": 5}},
                        "top_ip": {"terms": {"field": "src_ip.keyword", "size": 3}},
                    }
                }
            }
        )

        buckets = []
        for bkt in res["aggregations"]["hourly"]["buckets"]:
            sev_dist = {b["key"]: b["doc_count"] for b in bkt["by_sev"]["buckets"]}
            buckets.append({
                "ts":    bkt["key_as_string"][:13],
                "total": bkt["doc_count"],
                "critical": sev_dist.get("critical", 0),
                "high":     sev_dist.get("high",     0),
                "medium":   sev_dist.get("medium",   0),
                "low":      sev_dist.get("low",      0),
                "top_ips":  [b["key"] for b in bkt["top_ip"]["buckets"]],
            })

        return jsonify({"buckets": buckets, "window_hours": hours})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  SLA — statistiques & suivi
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/sla/stats")
@require_level("L1")
def api_sla_stats():
    """
    Statistiques SLA globales :
    - Incidents en breach / at_risk / ok par sévérité
    - MTTR moyen (closed incidents, last 30j)
    - MTTD moyen (detect time = created_at - first_log si dispo, sinon N/A)
    - Top 10 incidents en breach actifs
    """
    try:
        now = datetime.now(timezone.utc)

        # ── Incidents ouverts (calculer sla_status live) ──────────
        open_res = es.search(
            index="soc-incidents", size=500,
            query={"bool": {"must_not": [{"term": {"status.keyword": "resolved"}}]}},
            _source=["incident_id","title","severity","status","created_at",
                     "sla_deadline","sla_status","assigned_to","src_ip"]
        )
        breach, at_risk, ok_count = [], [], []
        by_sev = {s: {"breach": 0, "at_risk": 0, "ok": 0}
                  for s in ("critical", "high", "medium", "low")}
        for h in open_res["hits"]["hits"]:
            s    = h["_source"]
            sev  = s.get("severity", "medium")
            live = _sla_status(sev, s.get("created_at",""), None)
            entry = {**s, "_id": h["_id"], "sla_live": live}
            if live == "breached":
                breach.append(entry)
                by_sev.setdefault(sev, {"breach":0,"at_risk":0,"ok":0})["breach"] += 1
            elif live == "at_risk":
                at_risk.append(entry)
                by_sev.setdefault(sev, {"breach":0,"at_risk":0,"ok":0})["at_risk"] += 1
            else:
                ok_count.append(entry)
                by_sev.setdefault(sev, {"breach":0,"at_risk":0,"ok":0})["ok"] += 1

        # ── MTTR : incidents résolus sur 30j ──────────────────────
        resolved_res = es.search(
            index="soc-incidents", size=500,
            query={"bool": {"must": [
                {"term":  {"status.keyword": "resolved"}},
                {"range": {"closed_at": {"gte": "now-30d"}}}
            ]}},
            _source=["severity","created_at","closed_at"]
        )
        mttr_by_sev = {s: [] for s in ("critical","high","medium","low")}
        for h in resolved_res["hits"]["hits"]:
            s = h["_source"]
            try:
                dt_c = datetime.fromisoformat(s["created_at"].replace("Z","+00:00"))
                dt_r = datetime.fromisoformat(s["closed_at"].replace("Z","+00:00"))
                hours = (dt_r - dt_c).total_seconds() / 3600
                sev   = s.get("severity","medium")
                mttr_by_sev.setdefault(sev, []).append(hours)
            except Exception:
                pass

        def avg(lst): return round(sum(lst)/len(lst), 1) if lst else None

        mttr_summary = {
            sev: {
                "avg_hours":  avg(vals),
                "count":      len(vals),
                "sla_target": _SLA_HOURS.get(sev, 24),
                "met_sla":    sum(1 for v in vals if v <= _SLA_HOURS.get(sev,24)),
            }
            for sev, vals in mttr_by_sev.items()
        }

        # Top 10 breached incidents (par ancienneté)
        breach_sorted = sorted(breach, key=lambda x: x.get("created_at",""))[:10]

        return jsonify({
            "open_total":   len(open_res["hits"]["hits"]),
            "breached":     len(breach),
            "at_risk":      len(at_risk),
            "ok":           len(ok_count),
            "by_severity":  by_sev,
            "mttr":         mttr_summary,
            "top_breach":   breach_sorted,
            "sla_targets":  _SLA_HOURS,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  AbuseIPDB — réputation IP à la demande
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/ip/reputation/<path:ip>")
@require_level("L1")
def api_ip_reputation(ip):
    """Retourne le score AbuseIPDB pour une IP (cache 24h)."""
    if not _ABUSEIPDB_KEY:
        return jsonify({"error": "Clé AbuseIPDB non configurée (ABUSEIPDB_KEY)"}), 501
    rep = get_ip_reputation(ip)
    if rep is None:
        return jsonify({"error": "IP privée ou AbuseIPDB indisponible"}), 404
    return jsonify(rep)


# ═══════════════════════════════════════════════════════════════════════════════
#  AUTO-ESCALATION — thread de surveillance SLA + investigations bloquées
# ═══════════════════════════════════════════════════════════════════════════════

def _auto_escalation_loop():
    """
    Thread daemon lancé au démarrage.
    Toutes les 30 min :
      1. Investigations bloquées en 'new' depuis > 48h → escalade sévérité + notif L2/L3
      2. Incidents ouverts dépassant leur SLA → sla_status='breached' + notif L3
    """
    import time as _time
    _time.sleep(60)  # laisser l'app démarrer complètement
    while True:
        try:
            _run_escalation_check()
        except Exception as e:
            log.error(f"auto_escalation error: {e}")
        _time.sleep(1800)  # 30 min


def _run_escalation_check():
    now = datetime.now(timezone.utc)

    # ── 1. Investigations bloquées > 48h ──────────────────────────
    cutoff_48h = (now - timedelta(hours=48)).isoformat()
    stale_inv = es.search(
        index="soc-investigations", size=100,
        query={"bool": {"must": [
            {"term":  {"status.keyword": "new"}},
            {"range": {"created_at": {"lt": cutoff_48h}}}
        ]}},
        _source=["ip","severity","created_at","assigned_to","inv_id"]
    )
    SEV_UP = {"low": "medium", "medium": "high", "high": "critical", "critical": "critical"}
    users_all = _load_users()
    l2l3_users = [u for u, d in users_all.items() if d.get("level") in ("L2","L3") and d.get("active", True)]

    for h in stale_inv["hits"]["hits"]:
        s   = h["_source"]
        inv_id = h["_id"]
        old_sev = s.get("severity", "medium")
        new_sev = SEV_UP.get(old_sev, old_sev)
        age_h   = (now - datetime.fromisoformat(
            s.get("created_at","1970-01-01T00:00:00Z").replace("Z","+00:00")
        )).total_seconds() / 3600
        note_text = (f"[AUTO-ESCALADE] Investigation en attente depuis {int(age_h)}h "
                     f"sans prise en charge. Sévérité escaladée {old_sev}→{new_sev}.")
        try:
            doc = es.get(index="soc-investigations", id=inv_id)["_source"]
            doc["severity"]   = new_sev
            doc["status"]     = "new"
            doc["escalated"]  = True
            doc["updated_at"] = now.isoformat()
            notes = doc.get("notes", [])
            notes.append({"timestamp": now.isoformat()+"Z", "author": "système", "text": note_text})
            doc["notes"] = notes
            es.index(index="soc-investigations", id=inv_id, document=doc)
            audit_log("auto_escalation_investigation", details={"inv_id": inv_id, "new_sev": new_sev})
            for uname in l2l3_users:
                push_notif(uname,
                    f"⚠️ Investigation {s.get('inv_id', inv_id[:8])} ({s.get('ip','?')}) "
                    f"en attente {int(age_h)}h — escaladée {new_sev.upper()}",
                    notif_type="critical" if new_sev == "critical" else "warning",
                    severity=new_sev)
        except Exception as e:
            log.error(f"escalation inv {inv_id}: {e}")

    # ── 2. Incidents ouverts en breach SLA ────────────────────────
    open_inc = es.search(
        index="soc-incidents", size=500,
        query={"bool": {"must_not": [{"term": {"status.keyword": "resolved"}}]}},
        _source=["incident_id","title","severity","created_at","sla_status","assigned_to"]
    )
    l3_users = [u for u, d in users_all.items() if d.get("level") == "L3" and d.get("active", True)]

    for h in open_inc["hits"]["hits"]:
        s   = h["_source"]
        inc_id = h["_id"]
        sev  = s.get("severity", "medium")
        live = _sla_status(sev, s.get("created_at",""), None)
        old  = s.get("sla_status", "ok")
        if live != old:
            try:
                es.update(index="soc-incidents", id=inc_id,
                          body={"doc": {"sla_status": live, "updated_at": now.isoformat()+"Z"}})
                if live == "breached" and old != "breached":
                    iid = s.get("incident_id", inc_id[:8])
                    for uname in l3_users:
                        push_notif(uname,
                            f"🔴 SLA BREACH — Incident {iid} ({sev.upper()}) dépasse la deadline",
                            notif_type="critical", incident_id=inc_id, severity=sev)
                elif live == "at_risk" and old == "ok":
                    assignee = s.get("assigned_to","")
                    if assignee and assignee not in ("None",""):
                        push_notif(assignee,
                            f"⏰ SLA at risk — Incident {s.get('incident_id',inc_id[:8])} à traiter",
                            notif_type="warning", incident_id=inc_id, severity=sev)
            except Exception as e:
                log.error(f"sla update inc {inc_id}: {e}")

    log.info(f"auto_escalation: {len(stale_inv['hits']['hits'])} inv escaladées, "
             f"{len(open_inc['hits']['hits'])} incidents SLA vérifiés")


# Lancer le thread d'auto-escalade au démarrage
threading.Thread(target=_auto_escalation_loop, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
# RAG — Retrieval Augmented Generation (ChromaDB + nomic-embed-text + llama3)
# ══════════════════════════════════════════════════════════════════════════════
import sys as _sys
_RAG_DIR = os.path.join(os.path.dirname(__file__), "rag")
if _RAG_DIR not in _sys.path:
    _sys.path.insert(0, _RAG_DIR)

def _rag_available():
    try:
        import chromadb  # noqa
        return True
    except ImportError:
        return False

@app.route("/rag")
@require_auth
def rag_page():
    return render_template("rag.html")

@app.route("/api/rag/query", methods=["POST"])
@require_level("L1")
def api_rag_query():
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question vide"}), 400
    if not _rag_available():
        return jsonify({"error": "chromadb non installé"}), 503
    try:
        from rag_query import rag_answer
        result = rag_answer(question)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/rag/search", methods=["POST"])
@require_level("L1")
def api_rag_search():
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or "").strip()
    n = min(int(data.get("n", 5)), 10)
    if not query:
        return jsonify({"error": "query vide"}), 400
    if not _rag_available():
        return jsonify({"error": "chromadb non installé"}), 503
    try:
        from rag_query import search
        chunks = search(query, n=n)
        return jsonify({"chunks": chunks})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/rag/rebuild", methods=["POST"])
@require_level("L3")
def api_rag_rebuild():
    if not _rag_available():
        return jsonify({"error": "chromadb non installé"}), 503
    def _rebuild():
        try:
            from build_index import build_index
            return build_index()
        except Exception as e:
            log.error(f"RAG rebuild error: {e}")
            return 0
    import threading as _t
    result = {}
    def run():
        result["chunks"] = _rebuild()
    th = _t.Thread(target=run)
    th.start()
    th.join(timeout=120)
    return jsonify({"status": "ok", "chunks": result.get("chunks", 0)})

@app.route("/api/rag/status")
@require_level("L1")
def api_rag_status():
    if not _rag_available():
        return jsonify({"available": False, "reason": "chromadb non installé"})
    try:
        import chromadb
        from chromadb.utils.embedding_functions import OllamaEmbeddingFunction
        vectors_dir = os.path.join(_RAG_DIR, "vectors")
        client = chromadb.PersistentClient(path=vectors_dir)
        cols = [c.name for c in client.list_collections()]
        count = 0
        if "soc_knowledge" in cols:
            embed_fn = OllamaEmbeddingFunction(
                model_name="nomic-embed-text",
                url=f"{OLLAMA_URL}/api/embeddings"
            )
            col = client.get_collection("soc_knowledge", embedding_function=embed_fn)
            count = col.count()
        docs_dir = os.path.join(_RAG_DIR, "docs")
        pdfs = [f for f in os.listdir(docs_dir) if f.endswith(".pdf")] if os.path.isdir(docs_dir) else []
        return jsonify({
            "available": True,
            "collection": "soc_knowledge" if "soc_knowledge" in cols else None,
            "chunks": count,
            "pdfs": len(pdfs),
            "pdf_names": [p.replace(".pdf","") for p in sorted(pdfs)],
        })
    except Exception as e:
        return jsonify({"available": True, "error": str(e), "chunks": 0})


@app.route("/bot")
@require_auth
def page_bot():
    return render_template("chatbot.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
