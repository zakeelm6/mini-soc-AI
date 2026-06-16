"""
Crée le dashboard SOC Overview dans Kibana via l'API Saved Objects.
"""
import requests
import json

BASE = "http://localhost:5601"
AUTH = ("elastic", "changeme")
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
DATA_VIEW_ID = "28413f52-d6ec-418b-ad9b-c465d1371716"

def post(path, body):
    r = requests.post(f"{BASE}{path}", auth=AUTH, headers=HEADERS, json=body)
    if r.status_code not in (200, 201):
        print(f"ERREUR {r.status_code} sur {path}: {r.text[:300]}")
        return None
    return r.json()

# ─── 1. Métrique : total logs ───────────────────────────────────────────────
metric_viz = {
    "attributes": {
        "title": "Total Logs",
        "visState": json.dumps({
            "title": "Total Logs",
            "type": "metric",
            "params": {
                "addTooltip": True,
                "addLegend": False,
                "type": "metric",
                "metric": {
                    "percentageMode": False,
                    "useRanges": False,
                    "colorSchema": "Green to Red",
                    "metricColorMode": "None",
                    "colorsRange": [{"from": 0, "to": 10000}],
                    "labels": {"show": True},
                    "invertColors": False,
                    "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 60}
                }
            },
            "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}]
        }),
        "uiStateJSON": "{}",
        "description": "",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "index": DATA_VIEW_ID,
                "query": {"query": "", "language": "kuery"},
                "filter": []
            })
        }
    },
    "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DATA_VIEW_ID}]
}
r1 = post("/api/saved_objects/visualization", metric_viz)
metric_id = r1["id"] if r1 else None
print(f"[1] Total Logs viz : {metric_id}")

# ─── 2. Histogramme : volume de logs dans le temps ──────────────────────────
histogram_viz = {
    "attributes": {
        "title": "Volume de logs dans le temps",
        "visState": json.dumps({
            "title": "Volume de logs dans le temps",
            "type": "histogram",
            "params": {
                "type": "histogram",
                "grid": {"categoryLines": False},
                "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                                   "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100},
                                   "title": {}}],
                "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
                                "style": {}, "scale": {"type": "linear", "mode": "normal"},
                                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                                "title": {"text": "Nombre de logs"}}],
                "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                   "data": {"label": "Logs", "id": "1"},
                                   "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                   "lineWidth": 2, "showCircles": True}],
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
                "times": [],
                "addTimeMarker": False,
                "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}
            },
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                 "params": {"field": "@timestamp", "timeRange": {"from": "now-24h", "to": "now"},
                            "useNormalizedEsInterval": True, "scaleMetricValues": False,
                            "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}}
            ]
        }),
        "uiStateJSON": "{}",
        "description": "",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "index": DATA_VIEW_ID,
                "query": {"query": "", "language": "kuery"},
                "filter": []
            })
        }
    },
    "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DATA_VIEW_ID}]
}
r2 = post("/api/saved_objects/visualization", histogram_viz)
histogram_id = r2["id"] if r2 else None
print(f"[2] Histogram viz : {histogram_id}")

# ─── 3. Pie chart : répartition par log_type ────────────────────────────────
pie_viz = {
    "attributes": {
        "title": "Répartition par type de log",
        "visState": json.dumps({
            "title": "Répartition par type de log",
            "type": "pie",
            "params": {
                "type": "pie",
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
                "isDonut": True,
                "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
            },
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                 "params": {"field": "log_type.keyword", "orderBy": "1", "order": "desc", "size": 10,
                            "otherBucket": False, "otherBucketLabel": "Other",
                            "missingBucket": False, "missingBucketLabel": "Missing"}}
            ]
        }),
        "uiStateJSON": "{}",
        "description": "",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "index": DATA_VIEW_ID,
                "query": {"query": "", "language": "kuery"},
                "filter": []
            })
        }
    },
    "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DATA_VIEW_ID}]
}
r3 = post("/api/saved_objects/visualization", pie_viz)
pie_id = r3["id"] if r3 else None
print(f"[3] Pie chart viz : {pie_id}")

# ─── 4. Bar chart : logs par hôte ────────────────────────────────────────────
bar_viz = {
    "attributes": {
        "title": "Logs par machine source",
        "visState": json.dumps({
            "title": "Logs par machine source",
            "type": "histogram",
            "params": {
                "type": "histogram",
                "grid": {"categoryLines": False},
                "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                                   "style": {}, "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100},
                                   "title": {}}],
                "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
                                "style": {}, "scale": {"type": "linear", "mode": "normal"},
                                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                                "title": {"text": "Nombre de logs"}}],
                "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                   "data": {"label": "Logs", "id": "1"},
                                   "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                   "lineWidth": 2, "showCircles": True}],
                "addTooltip": True,
                "addLegend": True,
                "legendPosition": "right",
                "times": [],
                "addTimeMarker": False
            },
            "aggs": [
                {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
                 "params": {"field": "host.name.keyword", "orderBy": "1", "order": "desc", "size": 10,
                            "otherBucket": False, "missingBucket": False}}
            ]
        }),
        "uiStateJSON": "{}",
        "description": "",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "index": DATA_VIEW_ID,
                "query": {"query": "", "language": "kuery"},
                "filter": []
            })
        }
    },
    "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DATA_VIEW_ID}]
}
r4 = post("/api/saved_objects/visualization", bar_viz)
bar_id = r4["id"] if r4 else None
print(f"[4] Bar chart viz : {bar_id}")

# ─── 5. Dashboard ────────────────────────────────────────────────────────────
if not all([metric_id, histogram_id, pie_id, bar_id]):
    print("Une ou plusieurs visualisations ont échoué — dashboard non créé.")
    exit(1)

panels = [
    {"version": "8.0.0", "type": "visualization", "gridData": {"x": 0,  "y": 0, "w": 8,  "h": 6,  "i": "1"}, "panelIndex": "1", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_1"},
    {"version": "8.0.0", "type": "visualization", "gridData": {"x": 8,  "y": 0, "w": 40, "h": 12, "i": "2"}, "panelIndex": "2", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_2"},
    {"version": "8.0.0", "type": "visualization", "gridData": {"x": 0,  "y": 6, "w": 24, "h": 12, "i": "3"}, "panelIndex": "3", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_3"},
    {"version": "8.0.0", "type": "visualization", "gridData": {"x": 24, "y": 6, "w": 24, "h": 12, "i": "4"}, "panelIndex": "4", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_4"},
]

dashboard = {
    "attributes": {
        "title": "SOC Overview",
        "description": "Dashboard principal du mini-SOC",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {"name": "panel_1", "type": "visualization", "id": metric_id},
        {"name": "panel_2", "type": "visualization", "id": histogram_id},
        {"name": "panel_3", "type": "visualization", "id": pie_id},
        {"name": "panel_4", "type": "visualization", "id": bar_id},
    ]
}
r5 = post("/api/saved_objects/dashboard", dashboard)
if r5:
    print(f"\n[OK] Dashboard créé : http://localhost:5601/app/dashboards#/view/{r5['id']}")
    print(f"     URL publique   : http://192.168.50.10:5601/app/dashboards#/view/{r5['id']}")
