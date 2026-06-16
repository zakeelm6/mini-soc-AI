import requests, json

BASE = "http://localhost:5601"
AUTH = ("elastic", "changeme")
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}
DV_ID = "28413f52-d6ec-418b-ad9b-c465d1371716"
REF = [{"type": "index-pattern", "id": DV_ID, "name": "indexpattern-datasource-layer-layer1"}]

def post(path, body):
    r = requests.post(f"{BASE}{path}", auth=AUTH, headers=HEADERS, json=body)
    if r.status_code not in (200, 201):
        print(f"ERREUR {r.status_code} {path}: {r.text[:300]}")
        return None
    return r.json()

def lens(title, viz_type, state):
    return {"attributes": {"title": title, "visualizationType": viz_type, "state": state}, "references": REF}

def xy_state(query, series_type, x_col, x_def, y_col, split_col=None, split_def=None):
    columns = {
        x_col: x_def,
        y_col: {"label": "Count", "dataType": "number", "operationType": "count", "isBucketed": False, "scale": "ratio", "sourceField": "___records___"}
    }
    col_order = [x_col]
    if split_col and split_def:
        columns[split_col] = split_def
        col_order.append(split_col)
    col_order.append(y_col)
    layer = {"layerId": "layer1", "accessors": [y_col], "position": "top", "seriesType": series_type, "showGridlines": False, "xAccessor": x_col}
    if split_col:
        layer["splitAccessor"] = split_col
    return {
        "datasourceStates": {"formBased": {"layers": {"layer1": {"columnOrder": col_order, "columns": columns, "indexPatternId": DV_ID}}}},
        "visualization": {"legend": {"isVisible": True, "position": "right"}, "fittingFunction": "None", "layers": [layer]},
        "query": {"query": query, "language": "kuery"},
        "filters": []
    }

# ─── 1. Top 10 IPs attaquantes ───────────────────────────────────────────────
r1 = post("/api/saved_objects/lens", lens(
    "Top 10 IPs attaquantes", "lnsXY",
    xy_state("tags:ssh_failed", "bar_horizontal", "col_ip",
        {"label": "IP source", "dataType": "string", "operationType": "terms", "sourceField": "src_ip.keyword",
         "isBucketed": True, "params": {"size": 10, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc", "otherBucket": False}},
        "col_count")
))
id1 = r1["id"] if r1 else None
print(f"[1] Top IPs : {id1}")

# ─── 2. Tentatives SSH dans le temps ────────────────────────────────────────
r2 = post("/api/saved_objects/lens", lens(
    "Tentatives SSH échouées dans le temps", "lnsXY",
    xy_state("tags:ssh_failed", "line", "col_time",
        {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram", "sourceField": "@timestamp",
         "isBucketed": True, "params": {"interval": "auto"}},
        "col_count")
))
id2 = r2["id"] if r2 else None
print(f"[2] SSH timeline : {id2}")

# ─── 3. Volume de logs par type (area stacked) ───────────────────────────────
r3 = post("/api/saved_objects/lens", lens(
    "Volume de logs par type", "lnsXY",
    xy_state("", "area_stacked", "col_time",
        {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram", "sourceField": "@timestamp",
         "isBucketed": True, "params": {"interval": "auto"}},
        "col_count",
        "col_type",
        {"label": "Type", "dataType": "string", "operationType": "terms", "sourceField": "log_type.keyword",
         "isBucketed": True, "params": {"size": 5, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc", "otherBucket": True}}
    )
))
id3 = r3["id"] if r3 else None
print(f"[3] Volume area : {id3}")

# ─── 4. Répartition sévérité (donut) ────────────────────────────────────────
r4 = post("/api/saved_objects/lens", lens(
    "Répartition par sévérité", "lnsPie",
    {
        "datasourceStates": {"formBased": {"layers": {"layer1": {
            "columnOrder": ["col_sev", "col_count"],
            "columns": {
                "col_sev": {"label": "Sévérité", "dataType": "string", "operationType": "terms", "sourceField": "severity.keyword",
                            "isBucketed": True, "params": {"size": 10, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc", "otherBucket": False}},
                "col_count": {"label": "Nombre", "dataType": "number", "operationType": "count", "isBucketed": False, "scale": "ratio", "sourceField": "___records___"}
            },
            "indexPatternId": DV_ID
        }}}},
        "visualization": {"shape": "donut", "layers": [{"layerId": "layer1", "groups": ["col_sev"], "metric": "col_count", "numberDisplay": "percent", "categoryDisplay": "default", "legendDisplay": "default"}]},
        "query": {"query": "", "language": "kuery"},
        "filters": []
    }
))
id4 = r4["id"] if r4 else None
print(f"[4] Sévérité donut : {id4}")

# ─── 5. Comptes SSH ciblés ───────────────────────────────────────────────────
r5 = post("/api/saved_objects/lens", lens(
    "Comptes SSH ciblés", "lnsXY",
    xy_state("tags:ssh_failed", "bar_horizontal", "col_user",
        {"label": "Utilisateur", "dataType": "string", "operationType": "terms", "sourceField": "ssh_user.keyword",
         "isBucketed": True, "params": {"size": 10, "orderBy": {"type": "column", "columnId": "col_count"}, "orderDirection": "desc", "otherBucket": False}},
        "col_count")
))
id5 = r5["id"] if r5 else None
print(f"[5] Comptes ciblés : {id5}")

# ─── Dashboard ───────────────────────────────────────────────────────────────
ids = [id1, id2, id3, id4, id5]
if not all(ids):
    print("Une visualisation a échoué — dashboard non créé")
    exit(1)

panels = [
    {"version": "8.0.0", "type": "lens", "gridData": {"x": 0,  "y": 0,  "w": 24, "h": 15, "i": "1"}, "panelIndex": "1", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_1"},
    {"version": "8.0.0", "type": "lens", "gridData": {"x": 24, "y": 0,  "w": 24, "h": 15, "i": "2"}, "panelIndex": "2", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_2"},
    {"version": "8.0.0", "type": "lens", "gridData": {"x": 0,  "y": 15, "w": 32, "h": 15, "i": "3"}, "panelIndex": "3", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_3"},
    {"version": "8.0.0", "type": "lens", "gridData": {"x": 32, "y": 15, "w": 16, "h": 15, "i": "4"}, "panelIndex": "4", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_4"},
    {"version": "8.0.0", "type": "lens", "gridData": {"x": 0,  "y": 30, "w": 48, "h": 15, "i": "5"}, "panelIndex": "5", "embeddableConfig": {"enhancements": {}}, "panelRefName": "panel_5"},
]

r6 = post("/api/saved_objects/dashboard", {
    "attributes": {
        "title": "SOC - Analyse des attaques",
        "description": "Top IPs, SSH timeline, sévérité, volumes, comptes ciblés",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "hidePanelTitles": False}),
        "timeRestore": False,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}
    },
    "references": [
        {"name": "panel_1", "type": "lens", "id": id1},
        {"name": "panel_2", "type": "lens", "id": id2},
        {"name": "panel_3", "type": "lens", "id": id3},
        {"name": "panel_4", "type": "lens", "id": id4},
        {"name": "panel_5", "type": "lens", "id": id5},
    ]
})
if r6:
    print(f"\n[OK] Dashboard Lens créé :")
    print(f"     http://192.168.50.10:5601/app/dashboards#/view/{r6['id']}")
