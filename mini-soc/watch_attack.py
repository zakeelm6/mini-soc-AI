#!/usr/bin/env python3
"""
watch_attack.py — Surveillance en temps réel d'une IP attaquante

Usage : python3 watch_attack.py 192.168.50.20
        python3 watch_attack.py 192.168.50.20 --interval 5
"""
import sys
import time
import json
import os
import argparse
from datetime import datetime, timezone, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from config import ES_HOST, ES_USER, ES_PASSWORD
from elasticsearch import Elasticsearch

es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))

# ── Couleurs terminal ──────────────────────────────────────────────────────────
R  = "\033[1;31m"; Y  = "\033[1;33m"; G  = "\033[0;32m"
B  = "\033[0;34m"; C  = "\033[0;36m"; M  = "\033[0;35m"
W  = "\033[1;37m"; DIM = "\033[2m";   NC = "\033[0m"
SEV_COLOR = {"critical": R, "high": Y, "medium": C, "low": G, "info": DIM}

seen_logs      = set()
seen_incidents = set()
log_counts     = defaultdict(int)
first_seen     = None


def fmt_ts(ts):
    if not ts:
        return "?"
    return str(ts)[:19].replace("T", " ")


def _get_agent_name(target_ip):
    """Résout l'agent.name Filebeat depuis l'IP Tailscale."""
    try:
        r = es.search(index="soc-logs-*", size=0, aggs={
            "agents": {"terms": {"field": "agent.name.keyword", "size": 20}}})
        # Retourner tous les agents connus (on les surveille tous si IP inconnue)
        agents = [b["key"] for b in r["aggregations"]["agents"]["buckets"]]
        return agents
    except:
        return []


def watch(target_ip, interval=5):
    global first_seen
    # Résoudre l'agent Filebeat associé à l'IP cible
    agents = _get_agent_name(target_ip)
    # Exclure l'agent local
    local_agents = ["arthur-Standard-PC-Q35-ICH9-2009"]
    target_agents = [a for a in agents if a not in local_agents] or agents

    print(f"\n{W}{'═'*62}{NC}")
    print(f"  {R}⚡ SURVEILLANCE ATTAQUE EN DIRECT{NC}")
    print(f"  {W}Cible    :{NC} {Y}{target_ip}{NC}")
    print(f"  {W}Agent    :{NC} {', '.join(target_agents)}")
    print(f"  {W}SOC      :{NC} Logstash :5044 → ES → IA Detector")
    print(f"  {W}Démarré  :{NC} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{W}{'═'*62}{NC}\n")

    while True:
        now  = datetime.now(timezone.utc)
        since = (now - timedelta(seconds=interval + 2)).isoformat()

        # ── Nouveaux logs Filebeat ─────────────────────────────────────────────
        try:
            agent_filter = {"terms": {"agent.name.keyword": target_agents}} if target_agents else {"match_all": {}}
            r = es.search(
                index="soc-logs-*", size=50,
                query={"bool": {"must": [
                    agent_filter,
                    {"range": {"@timestamp": {"gte": since}}},
                    {"bool": {"should": [
                        {"terms": {"tags": ["ssh_failed","auth_failure","ids_alert","http_error"]}},
                        {"term":  {"severity.keyword": "high"}},
                        {"term":  {"severity.keyword": "critical"}},
                    ], "minimum_should_match": 1}},
                ]}},
                sort=[{"@timestamp": "asc"}],
                _source=["@timestamp","log_type","message","src_ip","severity",
                         "request","response","ssh_user","tags"],
            )
            for h in r["hits"]["hits"]:
                eid = h["_id"]
                if eid in seen_logs:
                    continue
                seen_logs.add(eid)
                if first_seen is None:
                    first_seen = datetime.now()
                s   = h["_source"]
                ts  = fmt_ts(s.get("@timestamp"))
                lt  = s.get("log_type", "?")
                sev = s.get("severity", "low")
                sc  = SEV_COLOR.get(sev, NC)
                log_counts[lt] += 1

                msg = s.get("message", "")[:100]
                req = s.get("request", "")
                code = s.get("response", "")
                user = s.get("ssh_user", "")
                tags = s.get("tags", [])

                # Format selon type
                if lt == "auth" or "ssh_failed" in tags:
                    detail = f"SSH user={user}" if user else msg[:60]
                elif lt == "apache_access":
                    detail = f"{code} {req[:60]}" if req else msg[:60]
                else:
                    detail = msg[:70]

                tag_str = ""
                if "ssh_failed" in tags:   tag_str = f" {R}[SSH FAILED]{NC}"
                elif "ssh_success" in tags: tag_str = f" {G}[SSH OK]{NC}"
                elif "http_error" in tags:  tag_str = f" {Y}[HTTP ERR]{NC}"
                elif "ids_alert" in tags:   tag_str = f" {R}[IDS ALERT]{NC}"

                print(f"  {DIM}{ts}{NC} {B}[{lt:12}]{NC} {sc}[{sev:8}]{NC}{tag_str}")
                print(f"    {DIM}{detail}{NC}")

        except Exception as e:
            print(f"  {R}[ERR logs] {e}{NC}")

        # ── Incidents créés/mis à jour ─────────────────────────────────────────
        try:
            r2 = es.search(
                index="soc-incidents", size=20,
                query={"bool": {"must": [
                    {"term":  {"src_ip.keyword": target_ip}},
                    {"range": {"updated_at": {"gte": since}}},
                ]}},
                sort=[{"updated_at": "desc"}],
                _source=["incident_id","title","severity","status","assigned_to",
                         "unified_score","votes","llm_verdict","created_at","updated_at"],
            )
            for h in r2["hits"]["hits"]:
                iid = h["_id"]
                src = h["_source"]
                key = f"{iid}:{src.get('status')}:{src.get('llm_verdict')}"
                if key in seen_incidents:
                    continue
                seen_incidents.add(key)
                sev = src.get("severity", "?")
                sc  = SEV_COLOR.get(sev, NC)
                score = src.get("unified_score") or "?"
                votes = src.get("votes") or "?"
                verdict = src.get("llm_verdict") or "—"
                status  = src.get("status", "?")
                assigned = src.get("assigned_to") or "Non assigné"

                print(f"\n  {W}{'▶'*50}{NC}")
                print(f"  {R}🚨 INCIDENT DÉTECTÉ{NC}  {sc}[{sev.upper()}]{NC}")
                print(f"  {W}ID       :{NC} {src.get('incident_id','?')}")
                print(f"  {W}Titre    :{NC} {src.get('title','?')}")
                print(f"  {W}Score IA :{NC} {score}  Votes: {votes}/4")
                print(f"  {W}Verdict  :{NC} {verdict}")
                print(f"  {W}Statut   :{NC} {status}  → assigné à: {assigned}")
                print(f"  {W}{'▶'*50}{NC}\n")

        except Exception as e:
            print(f"  {R}[ERR incidents] {e}{NC}")

        # ── Anomalies IA ───────────────────────────────────────────────────────
        try:
            r3 = es.search(
                index="soc-ensemble-anomalies", size=10,
                query={"bool": {"must": [
                    {"term":  {"src_ip.keyword": target_ip}},
                    {"range": {"@timestamp": {"gte": since}}},
                ]}},
                sort=[{"@timestamp": "desc"}],
                _source=["@timestamp","votes","unified_score","if_score","rf_score",
                         "dl_score","rate_count","llm_verdict"],
            )
            for h in r3["hits"]["hits"]:
                eid = h["_id"]
                if eid in seen_incidents:
                    continue
                seen_incidents.add(eid)
                s = h["_source"]
                votes = s.get("votes", 0)
                score = s.get("unified_score") or "?"
                if_s  = s.get("if_score", "?")
                rf_s  = s.get("rf_score", "?")
                dl_s  = s.get("dl_score", "?")
                ts    = fmt_ts(s.get("@timestamp"))
                print(f"  {M}[IA ANOMALY]{NC} {ts}  votes={votes}/4  score={score}")
                print(f"    IF={if_s}  RF={rf_s}  DL={dl_s}  rate={s.get('rate_count','?')}")

        except Exception:
            pass

        # ── Stats résumé toutes les 30s ────────────────────────────────────────
        elapsed = int((datetime.now() - first_seen).total_seconds()) if first_seen else 0
        if elapsed > 0 and elapsed % 30 < interval:
            print(f"\n  {C}── Résumé {elapsed}s ──{NC}")
            for lt, cnt in sorted(log_counts.items(), key=lambda x: -x[1]):
                print(f"    {lt:15} : {cnt} logs")
            print(f"    Incidents  : {len(seen_incidents)}")
            print()

        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip",       nargs="?", default="192.168.50.20")
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()

    try:
        watch(args.ip, args.interval)
    except KeyboardInterrupt:
        print(f"\n\n  {Y}Surveillance arrêtée.{NC}")
        print(f"  Logs capturés : {len(seen_logs)}")
        print(f"  Incidents     : {len(seen_incidents)}")
        sys.exit(0)
