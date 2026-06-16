"""
llm_analyzer.py — Analyse LLM des incidents de sécurité via Ollama (llama3)

Boucle d'apprentissage :
  1. Après chaque analyse réussie (confidence >= 0.80), le résultat est sauvegardé
     dans llm_memory.json comme exemple few-shot.
  2. Les analyses suivantes reçoivent 2-3 exemples passés dans leur prompt —
     Ollama s'améliore au fil du temps sans fine-tuning.
  3. rf_detector et dl_detector lisent les verdicts accumulés pour ré-entraîner
     leurs modèles sur des labels validés par le LLM.
"""
import json
import logging
import os
import threading
import requests
from datetime import datetime, timezone

log = logging.getLogger("llm_analyzer")

OLLAMA_URL      = os.getenv("OLLAMA_URL", "http://localhost:11434") + "/api/generate"
OLLAMA_MODEL    = "llama3"
TIMEOUT         = 240
LLM_MEMORY_PATH = os.path.join(os.path.dirname(__file__), "llm_memory.json")
MEMORY_MAX      = 50
MEMORY_MIN_CONF = 0.80

_llm_lock    = threading.Semaphore(1)
_memory_lock = threading.Lock()

# ── MITRE ATT&CK mapping : log_type / attack pattern → tactic + technique ─────
MITRE_MAP = {
    "auth":           {"tactic": "Credential Access",   "technique": "Brute Force",                "id": "T1110"},
    "ssh_brute":      {"tactic": "Credential Access",   "technique": "Brute Force — SSH",          "id": "T1110.004"},
    "web":            {"tactic": "Initial Access",       "technique": "Exploit Public-Facing App",  "id": "T1190"},
    "apache":         {"tactic": "Initial Access",       "technique": "Exploit Public-Facing App",  "id": "T1190"},
    "scan":           {"tactic": "Reconnaissance",       "technique": "Active Scanning",            "id": "T1595"},
    "network_scan":   {"tactic": "Reconnaissance",       "technique": "Network Service Discovery",  "id": "T1046"},
    "ids":            {"tactic": "Defense Evasion",      "technique": "Indicator Removal",          "id": "T1070"},
    "postexploit":    {"tactic": "Execution",            "technique": "Command & Scripting Interp", "id": "T1059"},
    "lateral":        {"tactic": "Lateral Movement",     "technique": "Remote Services — SSH",      "id": "T1021.004"},
    "exfil":          {"tactic": "Exfiltration",         "technique": "Exfiltration Over C2",       "id": "T1041"},
    "c2":             {"tactic": "Command & Control",    "technique": "Application Layer Protocol", "id": "T1071"},
    "anomaly":        {"tactic": "Discovery",            "technique": "Network Service Discovery",  "id": "T1046"},
    "default":        {"tactic": "Initial Access",       "technique": "Valid Accounts",             "id": "T1078"},
}

# CVSS score → ajustement de confiance LLM
CVSS_CONFIDENCE_BOOST = {
    (9.0, 10.0): +0.12,   # Critical
    (7.0,  9.0): +0.07,   # High
    (4.0,  7.0): +0.03,   # Medium
    (0.0,  4.0):  0.00,   # Low
}


def _mitre_for(log_type: str, attack_type: str = "") -> dict:
    """Retourne le mapping MITRE ATT&CK pour un type de log/attaque."""
    key = (log_type or "").lower()
    atk = (attack_type or "").lower()
    for k in MITRE_MAP:
        if k in key or k in atk:
            return MITRE_MAP[k]
    return MITRE_MAP["default"]


def _fetch_related_cves(es_client, log_type: str, attack_type: str = "", limit: int = 3) -> list:
    """
    Cherche dans soc-cve-alerts les CVEs récentes pertinentes pour ce type d'attaque.
    Retourne une liste de dicts {cve_id, cvss_score, description}.
    """
    if es_client is None:
        return []
    try:
        # Mots-clés liés au type d'attaque
        keywords = []
        lt = (log_type or "").lower()
        at = (attack_type or "").lower()
        if "auth" in lt or "ssh" in lt or "brute" in at:
            keywords = ["openssh", "ssh", "authentication"]
        elif "web" in lt or "apache" in lt or "http" in lt:
            keywords = ["apache", "nginx", "http", "web", "rce"]
        elif "scan" in lt:
            keywords = ["scanner", "nmap", "reconnaissance"]
        else:
            keywords = ["rce", "exploit", "remote"]

        query = {
            "bool": {
                "should": [{"match": {"description": kw}} for kw in keywords],
                "minimum_should_match": 1,
                "filter": [{"range": {"cvss_score": {"gte": 6.0}}}]
            }
        }
        r = es_client.search(
            index="soc-cve-alerts", size=limit,
            query=query,
            sort=[{"cvss_score": {"order": "desc"}}],
            _source=["cve_id", "cvss_score", "description", "published"]
        )
        return [h["_source"] for h in r["hits"]["hits"]]
    except Exception:
        return []


def _cvss_confidence_boost(cves: list) -> float:
    """Retourne le boost de confiance max basé sur le CVSS des CVEs liées."""
    if not cves:
        return 0.0
    max_cvss = max(float(c.get("cvss_score", 0)) for c in cves)
    for (lo, hi), boost in CVSS_CONFIDENCE_BOOST.items():
        if lo <= max_cvss <= hi:
            return boost
    return 0.0


SYSTEM_PROMPT = """SOC analyst. Reply ONLY with valid JSON:
{"verdict":"true_positive"|"false_positive"|"uncertain","attack_type":"SSH Brute Force","confidence":0.9,"summary":"one sentence","threat_level":"critique"|"haute"|"moyenne"|"faible","attacker_intent":"one phrase","mitre_tactic":"Credential Access","mitre_technique":"T1110","evidence":["string1","string2"],"actions":["action1","action2"],"false_positive_reason":null}
evidence and actions must be arrays of strings. mitre_tactic and mitre_technique are required. No text outside JSON."""


def _load_memory():
    """Charge les exemples mémorisés depuis llm_memory.json."""
    try:
        with open(LLM_MEMORY_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save_to_memory(analysis, incident_data):
    """
    Mémorise une analyse de haute confiance comme exemple few-shot.
    La mémoire est utilisée pour enrichir les prochains prompts Ollama.
    """
    if analysis.get("model") == "fallback":
        return
    conf = float(analysis.get("confidence", 0))
    if conf < MEMORY_MIN_CONF:
        return

    entry = {
        "src_ip":      incident_data.get("src_ip", ""),
        "log_type":    incident_data.get("log_type", ""),
        "score":       incident_data.get("anomaly_score", 0),
        "verdict":     analysis.get("verdict"),
        "attack_type": analysis.get("attack_type", ""),
        "confidence":  conf,
        "summary":     analysis.get("summary", ""),
        "evidence":    analysis.get("evidence", [])[:2],
        "actions":     analysis.get("actions", [])[:2],
        "saved_at":    datetime.now(timezone.utc).isoformat(),
    }

    with _memory_lock:
        memory = _load_memory()
        # Éviter les doublons exacts (même IP + verdict dans la dernière heure)
        key = f"{entry['src_ip']}_{entry['verdict']}"
        existing_keys = [f"{e['src_ip']}_{e['verdict']}" for e in memory[-10:]]
        if key not in existing_keys:
            memory.append(entry)
            if len(memory) > MEMORY_MAX:
                memory = memory[-MEMORY_MAX:]
            try:
                with open(LLM_MEMORY_PATH, "w") as f:
                    json.dump(memory, f, indent=2, ensure_ascii=False)
                log.info(f"Mémoire LLM mise à jour : {len(memory)} exemples")
            except Exception as e:
                log.error(f"Erreur sauvegarde mémoire: {e}")


def _build_fewshot_context():
    """
    Sélectionne 2-3 exemples passés (TP + FP si possible) pour enrichir le prompt.
    Cela permet à Ollama de s'améliorer sur le contexte spécifique de ce SOC.
    """
    memory = _load_memory()
    if not memory:
        return ""

    # Sélectionner 1 TP + 1 FP (si disponibles) + 1 autre
    tp_examples = [e for e in memory if e.get("verdict") == "true_positive"]
    fp_examples = [e for e in memory if e.get("verdict") == "false_positive"]
    selected = []
    if tp_examples:
        selected.append(tp_examples[-1])  # dernier TP connu
    if fp_examples:
        selected.append(fp_examples[-1])  # dernier FP connu
    if len(selected) < 2 and memory:
        selected.append(memory[-1])

    lines = ["\nEXEMPLES D'ANALYSES PASSÉES (apprendre de ces cas) :"]
    for i, ex in enumerate(selected[:3], 1):
        lines.append(
            f"  [{i}] IP={ex['src_ip']} score={ex['score']:.2f} log={ex['log_type']}"
            f" → verdict={ex['verdict']} type=\"{ex['attack_type']}\" conf={ex['confidence']:.2f}"
            f"\n      résumé: {ex['summary']}"
        )
    lines.append("  (Ces exemples viennent de ce SOC — adapte ton analyse au même contexte)\n")
    return "\n".join(lines)


def _fetch_recent_logs(es_client, src_ip, log_type, window="10m", size=8):
    """Récupère les logs récents pour le contexte LLM."""
    try:
        query = {"bool": {"must": [
            {"range": {"@timestamp": {"gte": f"now-{window}"}}}
        ]}}
        if src_ip:
            query["bool"]["must"].append({"term": {"src_ip": src_ip}})
        elif log_type:
            query["bool"]["must"].append({"term": {"log_type": log_type}})

        r = es_client.search(
            index="soc-logs*", size=size,
            query=query,
            sort=[{"@timestamp": {"order": "desc"}}],
            _source=["@timestamp", "message", "log_type", "src_ip", "ssh_user", "severity"]
        )
        return [h["_source"] for h in r["hits"]["hits"]]
    except Exception as e:
        log.error(f"Log fetch error: {e}")
        return []


def _build_prompt(incident_data, logs, cves=None, mitre=None):
    """Construit le prompt enrichi CVE/CVSS + MITRE ATT&CK pour le LLM."""
    src_ip    = incident_data.get("src_ip", "inconnue")
    log_type  = incident_data.get("log_type", "inconnu")
    score     = incident_data.get("anomaly_score", 0)
    severity  = incident_data.get("severity", "medium")
    ssh_user  = incident_data.get("ssh_user", "")
    ts        = incident_data.get("timestamp", "")[:19]

    if_s    = incident_data.get("if_score")
    rf_s    = incident_data.get("rf_score")
    dl_s    = incident_data.get("dl_score")
    rate    = incident_data.get("rate_count")
    votes   = incident_data.get("votes")

    model_scores_text = ""
    if any(v is not None for v in [if_s, rf_s, dl_s, rate]):
        model_scores_text = f"""
VOTES MODÈLES IA :
- Isolation Forest : {f"{float(if_s):.3f}" if if_s is not None else "N/A"} (seuil 0.25)
- Random Forest    : {f"{float(rf_s):.3f}" if rf_s is not None else "N/A"} (seuil 0.55)
- Autoencoder DL   : {f"{float(dl_s):.3f}" if dl_s is not None else "N/A"} (seuil 0.30)
- Rate SSH/5min    : {rate if rate is not None else "N/A"} tentatives (seuil 10)
- Votes concordants: {votes if votes is not None else "N/A"}/4
  Si désaccord entre modèles → uncertainty possible"""

    # ── MITRE ATT&CK context ────────────────────────────────────────────────
    mitre = mitre or _mitre_for(log_type, incident_data.get("attack_type", ""))
    mitre_text = (
        f"\nCONTEXTE MITRE ATT&CK :\n"
        f"- Tactic    : {mitre['tactic']}\n"
        f"- Technique : {mitre['technique']} ({mitre['id']})\n"
        f"  → Utilise ces valeurs dans les champs mitre_tactic et mitre_technique de ta réponse JSON."
    )

    # ── CVE/CVSS context ─────────────────────────────────────────────────────
    cve_text = ""
    if cves:
        cve_lines = []
        for c in cves[:3]:
            cvss = float(c.get("cvss_score", 0))
            cve_id = c.get("cve_id", "?")
            desc = str(c.get("description", ""))[:120]
            severity_label = "CRITIQUE" if cvss >= 9.0 else "ÉLEVÉ" if cvss >= 7.0 else "MOYEN"
            cve_lines.append(f"  - {cve_id} | CVSS {cvss}/10 [{severity_label}] : {desc}")
        cve_text = (
            f"\nCVEs PERTINENTES (NVD — liées à ce type d'attaque) :\n"
            + "\n".join(cve_lines) +
            "\n  → Un CVSS ≥ 7.0 augmente la probabilité true_positive. "
            "Intègre ces CVEs dans ton analyse et tes actions recommandées."
        )

    logs_text = ""
    for i, l in enumerate(logs[:8], 1):
        msg  = str(l.get("message", ""))[:120]
        lt   = l.get("log_type", "")
        t    = str(l.get("@timestamp", ""))[:19]
        ip   = l.get("src_ip", "")
        user = l.get("ssh_user", "")
        logs_text += f"  [{i}] {t} | type={lt} | ip={ip} | user={user}\n      msg: {msg}\n"

    fewshot = _build_fewshot_context()

    prompt = f"""Analyse cet incident de sécurité détecté par notre SIEM :{fewshot}
INCIDENT:
- Timestamp     : {ts}
- IP source     : {src_ip}
- Type de log   : {log_type}
- SSH user      : {ssh_user or "N/A"}
- Score unifié  : {score:.3f}/1.0
- Sévérité IA   : {severity}
- Nb logs/10min : {len(logs)}
{model_scores_text}
{mitre_text}
{cve_text}

LOGS BRUTS (derniers {len(logs)}) :
{logs_text if logs_text else "  (aucun log disponible)"}

Analyse et réponds en JSON structuré (inclure mitre_tactic, mitre_technique)."""

    return prompt


def _quantitative_prefilter(incident_data, logs):
    """
    Pré-filtre basé sur des seuils quantitatifs clairs.
    Évite d'appeler Ollama quand l'évidence est écrasante → réduit les 'uncertain'.
    Retourne (verdict, confidence, reason) ou None si incertain.
    """
    score    = float(incident_data.get("anomaly_score", 0))
    rate     = int(incident_data.get("rate_count") or 0)
    if_s     = float(incident_data.get("if_score") or 0)
    votes    = int(incident_data.get("votes") or 0)

    # Compter les indices dans les logs
    ssh_fails  = sum(1 for l in logs if any(x in str(l.get("message","")).lower() for x in ["failed","invalid user","failure"]))
    ssh_ok     = sum(1 for l in logs if "session opened" in str(l.get("message","")).lower())
    web_attack = sum(1 for l in logs if any(x in str(l.get("message","")).lower() for x in ["union select","etc/passwd","nikto","sqlmap",".php?"]))

    # TP évident : brute force massif ou scan web agressif
    if ssh_fails >= 20 and rate >= 15:
        return ("true_positive", 0.95,
                f"SSH brute force massif : {ssh_fails} échecs dans les logs, rate={rate}/5min")
    if ssh_fails >= 30:
        return ("true_positive", 0.92, f"Brute force SSH intensif : {ssh_fails} tentatives échouées")
    if web_attack >= 3:
        return ("true_positive", 0.90, f"Attaque web détectée : {web_attack} signatures malveillantes")
    if score >= 0.85 and votes >= 3:
        return ("true_positive", 0.88, f"Score très élevé ({score:.2f}) et {votes}/4 modèles votants")

    # FP évident : très peu d'activité et score faible
    if ssh_fails == 0 and ssh_ok == 0 and rate < 2 and score < 0.35:
        return ("false_positive", 0.85, f"Aucune activité SSH suspecte, score faible ({score:.2f}), rate={rate}/5min")
    if ssh_ok > ssh_fails * 3 and score < 0.40:
        return ("false_positive", 0.82, f"Beaucoup plus de succès SSH ({ssh_ok}) que d'échecs ({ssh_fails}) → connexions légitimes")

    return None  # incertain → appeler Ollama


def analyze_incident(es_client, incident_data):
    """
    Analyse un incident avec llama3 via Ollama.
    Enrichi avec CVE/CVSS (NVD) + MITRE ATT&CK pour un scoring plus précis.
    """
    src_ip     = incident_data.get("src_ip", "")
    log_type   = incident_data.get("log_type", "")
    attack_type = incident_data.get("attack_type", "")

    # 1. Logs de contexte
    logs = _fetch_recent_logs(es_client, src_ip, log_type)

    # 2. CVEs pertinentes + MITRE (enrichissement)
    cves  = _fetch_related_cves(es_client, log_type, attack_type)
    mitre = _mitre_for(log_type, attack_type)
    cvss_boost = _cvss_confidence_boost(cves)

    if cves:
        log.info(f"CVE enrichment [{src_ip}]: {len(cves)} CVEs — boost confiance +{cvss_boost:.2f}")

    # 3. Pré-filtre quantitatif (cas évidents)
    prefilter = _quantitative_prefilter(incident_data, logs)
    if prefilter:
        verdict, confidence, reason = prefilter
        # Appliquer le boost CVSS sur la confiance
        confidence = min(0.99, confidence + cvss_boost)
        threat = "critique" if verdict == "true_positive" else "faible"
        atk_type = ("SSH Brute Force" if "SSH" in reason
                    else "Web Attack" if "web" in reason.lower()
                    else attack_type or "Anomalie réseau")
        log.info(f"Pré-filtre [{src_ip}]: {verdict} (conf={confidence:.2f}) — {reason}")
        cve_ids = [c.get("cve_id", "") for c in cves]
        analysis = {
            "verdict":            verdict,
            "confidence":         confidence,
            "attack_type":        atk_type,
            "summary":            reason,
            "threat_level":       threat,
            "attacker_intent":    "Accès non autorisé" if verdict == "true_positive" else "Activité normale",
            "mitre_tactic":       mitre["tactic"],
            "mitre_technique":    f"{mitre['technique']} ({mitre['id']})",
            "related_cves":       cve_ids,
            "max_cvss":           max((float(c.get("cvss_score", 0)) for c in cves), default=None),
            "evidence":           [reason] + cve_ids[:2],
            "actions":            (["Bloquer IP source", f"Patcher CVEs : {', '.join(cve_ids[:2])}"]
                                   if verdict == "true_positive" and cve_ids
                                   else ["Bloquer IP source"] if verdict == "true_positive"
                                   else ["Surveiller"]),
            "false_positive_reason": None if verdict == "true_positive" else reason,
            "analyzed_at":        datetime.now(timezone.utc).isoformat(),
            "model":              "prefilter+cve",
            "logs_used":          len(logs),
        }
        _save_to_memory(analysis, incident_data)
        return analysis

    # 4. Prompt enrichi → Ollama llama3
    prompt = _build_prompt(incident_data, logs, cves=cves, mitre=mitre)

    payload = {
        "model":  OLLAMA_MODEL,
        "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 420,   # +70 tokens pour MITRE + CVE
        }
    }

    if not _llm_lock.acquire(timeout=10):
        log.warning(f"LLM occupé, skip pour {src_ip}")
        return _fallback_analysis(incident_data)

    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=TIMEOUT)
        resp.raise_for_status()
        raw = resp.json().get("response", "").strip()

        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start == -1 or end == 0:
            log.warning(f"LLM pas de JSON valide: {raw[:100]}")
            return _fallback_analysis(incident_data)

        analysis = json.loads(raw[start:end])

        # Appliquer boost CVSS sur la confiance retournée par le LLM
        base_conf = float(analysis.get("confidence", 0.5))
        analysis["confidence"] = min(0.99, base_conf + cvss_boost)

        # Compléter les champs MITRE si LLM ne les a pas fournis
        if not analysis.get("mitre_tactic"):
            analysis["mitre_tactic"] = mitre["tactic"]
        if not analysis.get("mitre_technique"):
            analysis["mitre_technique"] = f"{mitre['technique']} ({mitre['id']})"

        # Ajouter métadonnées CVE
        analysis["related_cves"] = [c.get("cve_id", "") for c in cves]
        analysis["max_cvss"]     = max((float(c.get("cvss_score", 0)) for c in cves), default=None)
        analysis["analyzed_at"]  = datetime.now(timezone.utc).isoformat()
        analysis["model"]        = OLLAMA_MODEL
        analysis["logs_used"]    = len(logs)

        log.info(
            f"LLM [{OLLAMA_MODEL}] [{src_ip}] → "
            f"verdict={analysis.get('verdict')} conf={analysis.get('confidence'):.2f} "
            f"mitre={analysis.get('mitre_tactic')} cves={len(cves)} cvss_boost=+{cvss_boost:.2f}"
        )

        _save_to_memory(analysis, incident_data)
        return analysis

    except requests.exceptions.Timeout:
        log.warning(f"LLM timeout {TIMEOUT}s pour {src_ip}")
        return _fallback_analysis(incident_data)
    except json.JSONDecodeError as e:
        log.warning(f"JSON parse error: {e} — raw: {raw[:200]}")
        return _fallback_analysis(incident_data)
    except Exception as e:
        log.error(f"LLM error: {e}")
        return None
    finally:
        _llm_lock.release()


def _fallback_analysis(incident_data):
    """Analyse de secours si le LLM échoue — avec MITRE ATT&CK."""
    score      = incident_data.get("anomaly_score", 0)
    log_type   = incident_data.get("log_type", "")
    attack_type = incident_data.get("attack_type", "")
    src_ip     = incident_data.get("src_ip", "")
    mitre      = _mitre_for(log_type, attack_type)

    if log_type == "auth" and score >= 0.4:
        return {
            "verdict":             "true_positive",
            "attack_type":         "SSH Brute Force",
            "confidence":          0.75,
            "summary":             f"Volume anormal d'authentifications SSH depuis {src_ip}.",
            "threat_level":        "haute",
            "attacker_intent":     "Obtenir un accès SSH par force brute",
            "mitre_tactic":        mitre["tactic"],
            "mitre_technique":     f"{mitre['technique']} ({mitre['id']})",
            "evidence":            ["Volume élevé de tentatives SSH", f"Score anomalie: {score:.2f}"],
            "actions":             ["Bloquer l'IP avec iptables", "Activer fail2ban", "Vérifier les connexions réussies"],
            "false_positive_reason": None,
            "analyzed_at":         datetime.now(timezone.utc).isoformat(),
            "model":               "fallback",
            "logs_used":           0,
        }
    return {
        "verdict":             "uncertain",
        "attack_type":         attack_type or "Activité suspecte",
        "confidence":          0.5,
        "summary":             "Analyse automatique non disponible.",
        "threat_level":        "moyenne",
        "attacker_intent":     "Inconnu",
        "mitre_tactic":        mitre["tactic"],
        "mitre_technique":     f"{mitre['technique']} ({mitre['id']})",
        "evidence":            [f"Score anomalie: {score:.2f}"],
        "actions":             ["Investiguer manuellement les logs"],
        "false_positive_reason": None,
        "analyzed_at":         datetime.now(timezone.utc).isoformat(),
        "model":               "fallback",
        "logs_used":           0,
    }
