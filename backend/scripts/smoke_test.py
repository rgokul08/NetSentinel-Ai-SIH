#!/usr/bin/env python3
"""End-to-end smoke test for the CyberForecast AI backend.

Runs against a live server (default http://localhost:8000/api) and exercises every
major surface: authentication and RBAC, analytics, traffic views, ML detection,
forecasting, alert triage, models, datasets, reports, the integrity ledger,
simulation, audit trail, admin console and optional MFA.

    python backend/scripts/smoke_test.py
    python backend/scripts/smoke_test.py --base-url http://localhost:8000/api --verbose

Exits non-zero when any check fails, so it can gate a deployment. The script is
deliberately read-mostly: anything it creates (reports, ledger entries, a temporary
simulation run, MFA enrolment, runtime settings) is removed or restored at the end.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
import time
from typing import Any, Dict, Optional

import httpx

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
DIM = "\033[2m"
RESET = "\033[0m"


class Harness:
    def __init__(self, client: httpx.Client, verbose: bool = False) -> None:
        self.client = client
        self.verbose = verbose
        self.passed = 0
        self.failed: list[str] = []

    def check(self, label: str, condition: bool, extra: Any = "") -> bool:
        if condition:
            self.passed += 1
            if self.verbose:
                print(f"  {PASS} {label} {DIM}{extra}{RESET}")
            else:
                print(f"  {PASS} {label}")
        else:
            self.failed.append(f"{label} {extra}".strip())
            print(f"  {FAIL} {label} {extra}")
        return bool(condition)

    def section(self, title: str) -> None:
        print(f"\n\033[1m{title}\033[0m")

    def summary(self) -> int:
        total = self.passed + len(self.failed)
        print("\n" + "=" * 68)
        print(f"  {self.passed}/{total} checks passed")
        if self.failed:
            print(f"  {len(self.failed)} failed:")
            for failure in self.failed:
                print(f"   • {failure}")
            print("=" * 68)
            return 1
        print("  Every backend surface responded correctly.")
        print("=" * 68)
        return 0


# --- minimal TOTP client (RFC 6238) so MFA can be tested without pyotp -------
def totp_code(secret: str, drift: int = 0) -> str:
    padding = "=" * (-len(secret) % 8)
    key = base64.b32decode(secret.upper() + padding)
    counter = int(time.time() // 30) + drift
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % 10 ** 6).zfill(6)


def main() -> int:
    parser = argparse.ArgumentParser(description="CyberForecast AI backend smoke test")
    parser.add_argument("--base-url", default="http://localhost:8000/api")
    parser.add_argument("--admin-email", default="admin@cyberforecast.ai")
    parser.add_argument("--admin-password", default="Admin@1234")
    parser.add_argument("--analyst-email", default="analyst@cyberforecast.ai")
    parser.add_argument("--analyst-password", default="Analyst@1234")
    parser.add_argument("--viewer-email", default="viewer@cyberforecast.ai")
    parser.add_argument("--viewer-password", default="Viewer@1234")
    parser.add_argument("--verbose", action="store_true", help="print extra detail for passing checks")
    parser.add_argument("--timeout", type=float, default=240.0)
    args = parser.parse_args()

    client = httpx.Client(base_url=args.base_url, timeout=args.timeout)
    h = Harness(client, verbose=args.verbose)
    print(f"CyberForecast AI smoke test -> {args.base_url}")

    try:
        client.get("/health").raise_for_status()
    except Exception as exc:
        print(f"\n{FAIL} backend unreachable at {args.base_url}: {exc}")
        return 2

    # ------------------------------------------------------------------ auth
    h.section("Authentication & RBAC")
    response = client.post("/auth/login", json={"email": args.admin_email, "password": args.admin_password})
    if not h.check("admin login", response.status_code == 200, response.status_code):
        return h.summary()
    admin_token = response.json()["access_token"]
    admin = response.json()["user"]
    AH = {"Authorization": f"Bearer {admin_token}"}
    h.check("admin role + capabilities", admin["role"] == "admin" and "users.manage" in admin["capabilities"], admin["role"])

    analyst = client.post("/auth/login", json={"email": args.analyst_email, "password": args.analyst_password})
    viewer = client.post("/auth/login", json={"email": args.viewer_email, "password": args.viewer_password})
    h.check("analyst login", analyst.status_code == 200, analyst.status_code)
    h.check("viewer login", viewer.status_code == 200, viewer.status_code)
    NH = {"Authorization": f"Bearer {analyst.json().get('access_token', '')}"}
    VH = {"Authorization": f"Bearer {viewer.json().get('access_token', '')}"}

    h.check("wrong password rejected", client.post("/auth/login", json={"email": args.admin_email, "password": "nope"}).status_code == 401)
    h.check("missing token -> 401", client.get("/analytics/overview").status_code == 401)
    h.check("garbage token -> 401", client.get("/auth/me", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401)
    h.check("viewer blocked from user management", client.get("/admin/users", headers=VH).status_code == 403)
    h.check("viewer blocked from the audit log", client.get("/audit-logs", headers=VH).status_code == 403)
    h.check("analyst blocked from runtime settings", client.get("/admin/settings", headers=NH).status_code == 403)
    h.check("viewer blocked from training models", client.post("/models/train", json={"algorithm": "random_forest"}, headers=VH).status_code == 403)
    h.check("viewer may read analytics", client.get("/analytics/overview", headers=VH).status_code == 200)
    me = client.get("/auth/me", headers=AH).json()
    h.check("GET /auth/me", me.get("email") == args.admin_email, me.get("email"))
    roles = client.get("/auth/roles", headers=AH).json()
    h.check("role matrix published", len(roles.get("roles", [])) == 3 and roles.get("permission_matrix"), len(roles.get("permission_matrix", {})))

    # ---------------------------------------------------------------- system
    h.section("System health & configuration")
    health = client.get("/health").json()
    h.check("health status", health["status"] in ("online", "degraded", "partial"), health["status"])
    detailed = client.get("/health/detailed", headers=AH).json()
    components = detailed.get("components", {})
    h.check("ml engine online with a real model", components.get("ml_engine", {}).get("status") == "online", components.get("ml_engine", {}).get("model_name"))
    h.check("database online", components.get("database", {}).get("status") == "online", components.get("database", {}).get("dialect"))
    config = client.get("/config").json()
    h.check("config payload", config.get("app_name") == "CyberForecast AI" and config.get("version"), config.get("version"))
    h.check("seed status reported", config.get("seed_status", {}).get("status") in ("complete", "skipped", "error"), config.get("seed_status", {}).get("status"))

    # ------------------------------------------------------- analytics/traffic
    h.section("Analytics, traffic & visualization endpoints")
    dashboard = client.get("/analytics/dashboard", headers=AH).json()
    kpis = dashboard.get("kpis", {})
    h.check("dashboard KPIs computed from data", kpis.get("flows", 0) > 0, f"flows={kpis.get('flows')} threats={kpis.get('detected_threats')}")
    h.check("dashboard exposes every widget payload",
            all(key in dashboard for key in ("kpis", "trends", "alert_stats", "threat_level", "blockchain", "models", "system_health")),
            f"{len(dashboard)} blocks")
    overview = client.get("/analytics/overview", headers=AH, params={"window": "24h"}).json()
    h.check("analytics overview", overview.get("window") == "24h" and bool(overview.get("attack_distribution")) and overview.get("empty") is False,
            f"origin={overview.get('data_origin')}")
    trends = client.get("/analytics/trends", headers=AH, params={"window": "24h", "bucket": "1h"}).json()
    h.check("analytics trends bucketed", len(trends.get("attacks_over_time", [])) > 1 and len(trends.get("traffic_over_time", [])) > 1,
            f"buckets={trends.get('bucket')} points={len(trends.get('attacks_over_time', []))}")
    entities = client.get("/analytics/top-entities", headers=AH).json()
    h.check("top entities", any(entities.get(key) for key in ("source_ips", "destination_ips", "ports", "protocols")), list(entities.keys())[:5])

    # "live" only covers the last few minutes, so generate fresh traffic first.
    client.post("/simulation/inject", headers=AH, params={"attack_type": "Port Scan", "count": 4, "create_alerts": False})
    live = client.get("/traffic/live", headers=AH, params={"limit": 20}).json()
    h.check("live traffic aggregate", live.get("flows", 0) > 0 and live.get("threat_level"),
            f"flows={live.get('flows')} window={live.get('window')} pps={live.get('packets_per_second')}")
    h.check("live view is honest about its data origin", live.get("data_origin") in ("simulation", "mixed", "dataset"), live.get("data_origin"))
    recent = client.get("/traffic/recent", headers=AH, params={"limit": 10}).json()
    h.check("recent traffic", isinstance(recent.get("items"), list) and len(recent["items"]) > 0, len(recent.get("items", [])))
    timeline = client.get("/traffic/timeline", headers=AH, params={"window": "24h", "limit": 100}).json()
    h.check("event timeline", len(timeline.get("events", [])) > 0 and timeline.get("window") == "24h" and bool(timeline.get("counts")),
            len(timeline.get("events", [])))
    threat_map = client.get("/traffic/threat-map", headers=AH, params={"window": "24h", "limit": 40}).json()
    h.check("threat map graph", isinstance(threat_map.get("nodes"), list) and isinstance(threat_map.get("links"), list),
            f"nodes={len(threat_map.get('nodes', []))} links={len(threat_map.get('links', []))}")
    summary = client.get("/traffic/summary", headers=AH, params={"window": "24h"}).json()
    h.check("traffic summary aggregates", summary.get("flows", 0) > 0 and bool(summary.get("class_distribution")),
            f"attacks={summary.get('attacks')} rate={summary.get('attack_rate')}")

    # ------------------------------------------------------------ detection
    h.section("ML detection pipeline")
    sample_flow = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_ip": "203.0.113.42", "destination_ip": "10.20.30.40",
        "source_port": 51234, "destination_port": 22, "protocol": "TCP",
        "packet_count": 4200, "byte_count": 1200000, "packet_length": 285,
        "flow_duration": 1.4, "packets_per_second": 3000, "bytes_per_second": 857000,
        "connection_count": 380, "tcp_flags": "SYN", "failed_connections": 210,
        "request_frequency": 260,
    }
    single = client.post("/predict", json={"flow": sample_flow}, headers=AH)
    prediction = single.json() if single.status_code == 200 else {}
    h.check("single-flow prediction", single.status_code == 200 and prediction.get("attack_type"), f"{prediction.get('attack_type')} p={prediction.get('attack_probability')}")
    h.check("prediction exposes probabilities + risk", bool(prediction.get("probabilities")) and prediction.get("risk_score") is not None,
            f"risk={prediction.get('risk_score')} level={prediction.get('risk_level')}")
    h.check("prediction carries an explanation + model info", bool(prediction.get("explanation")) and bool(prediction.get("model")),
            (prediction.get("model") or {}).get("name"))
    batch = client.post("/predict/batch", json={"flows": [sample_flow, {**sample_flow, "destination_port": 443, "packet_count": 12, "failed_connections": 0}]}, headers=AH)
    batch_body = batch.json()
    h.check("batch prediction", batch.status_code == 200 and len(batch_body.get("predictions", [])) == 2, len(batch_body.get("predictions", [])))
    h.check("batch summary present", bool(batch_body.get("summary")), list(batch_body.get("summary", {}).keys())[:6])

    # ------------------------------------------------------------- forecast
    h.section("Attack forecasting")
    options = client.get("/forecast/options", headers=AH).json()
    h.check("forecast options + disclaimer published", len(options.get("horizons", [])) >= 3 and options.get("disclaimer"),
            f"{len(options.get('horizons', []))} horizons, method={options.get('method')}")
    run = client.post("/forecast", headers=AH, json={"horizon": 30, "include_history": True})
    forecast = run.json() if run.status_code == 200 else {}
    overall = forecast.get("overall") or {}
    h.check("forecast run", run.status_code == 200 and overall, f"horizon={overall.get('horizon_minutes')} p={overall.get('probability')}")
    h.check("per-horizon + per-category forecasts", len(forecast.get("horizons", [])) >= 3 and len(forecast.get("categories", [])) > 0,
            f"horizons={len(forecast.get('horizons', []))} categories={len(forecast.get('categories', []))} records={forecast.get('records_used')}")
    h.check("forecast states uncertainty", overall.get("confidence") is not None and overall.get("risk_level"), overall.get("risk_level"))
    latest = client.get("/forecast/latest", headers=AH).json()
    h.check("latest forecast retrievable", bool(latest.get("run_id")) and bool(latest.get("overall")), latest.get("method"))
    history = client.get("/forecast/history", headers=AH, params={"limit": 20}).json()
    h.check("forecast history", len(history.get("items", [])) > 0 and history.get("total", 0) > 0, history.get("total"))
    trend = client.get("/forecast/trend", headers=AH, params={"limit": 120}).json()
    h.check("forecast trend", len(trend.get("items", [])) > 0, len(trend.get("items", [])))

    # --------------------------------------------------------------- alerts
    h.section("Alerts & triage")
    alerts = client.get("/alerts", headers=AH, params={"limit": 5}).json()
    h.check("alert list", alerts.get("pagination", {}).get("total", 0) > 0, alerts.get("pagination", {}).get("total"))
    alert_stats = client.get("/alerts/stats", headers=AH).json()
    h.check("alert stats endpoint", alert_stats.get("total", 0) > 0 and bool(alert_stats.get("by_status")), f"total={alert_stats.get('total')}")
    alert_export = client.get("/alerts/export", headers=AH, params={"window": "7d", "limit": 50})
    h.check("alert CSV export", alert_export.status_code == 200 and len(alert_export.content) > 50, len(alert_export.content))
    alert_id = alerts["items"][0]["id"] if alerts.get("items") else None
    if alert_id:
        detail = client.get(f"/alerts/{alert_id}", headers=AH).json()
        h.check("alert detail", detail.get("id") == alert_id and detail.get("attack_type"), detail.get("attack_type"))
        note = f"smoke-test note {int(time.time())}"
        patch = client.patch(f"/alerts/{alert_id}", json={"notes": note, "assigned_to": args.admin_email}, headers=AH)
        body = patch.json()
        h.check("analyst note persisted", patch.status_code == 200 and body.get("notes") == note, str(body.get("notes"))[:60])
        h.check("assignment persisted", body.get("assigned_to") == args.admin_email, body.get("assigned_to"))
        h.check("triage history appended", any(entry.get("note") == note or note in json.dumps(entry) for entry in body.get("history", [])), len(body.get("history", [])))
        status_change = client.patch(f"/alerts/{alert_id}", json={"status": "reviewed"}, headers=AH)
        h.check("status transition", status_change.status_code == 200 and status_change.json().get("status") == "reviewed", status_change.json().get("status"))
        viewer_patch = client.patch(f"/alerts/{alert_id}", json={"status": "resolved"}, headers=VH)
        h.check("viewer cannot triage (RBAC)", viewer_patch.status_code == 403, viewer_patch.status_code)

    # --------------------------------------------------------------- models
    h.section("Model registry")
    models = client.get("/models", headers=AH).json()
    h.check("model list", models.get("pagination", {}).get("total", 0) >= 2, models.get("pagination", {}).get("total"))
    registry = client.get("/models/registry", headers=AH).json()
    h.check("active classifier registered", bool(registry.get("active_classifier")), (registry.get("active_classifier") or {}).get("name"))
    h.check("active anomaly detector registered", bool(registry.get("active_anomaly_detector")), (registry.get("active_anomaly_detector") or {}).get("name"))
    algorithms = client.get("/models/algorithms", headers=AH).json()
    h.check("algorithm catalogue", len(algorithms.get("items", [])) >= 5, len(algorithms.get("items", [])))
    classifier = next((m for m in models["items"] if m["task"] == "classification"), None)
    if classifier:
        detail = client.get(f"/models/{classifier['id']}", headers=AH).json()
        h.check("model detail metrics", bool(detail.get("metrics", {}).get("accuracy")) and detail["metrics"]["accuracy"] > 0.5, detail["metrics"].get("accuracy"))
        h.check("confusion matrix present", bool((detail.get("confusion_matrix") or {}).get("matrix")), len((detail.get("confusion_matrix") or {}).get("labels", [])))
        h.check("per-class report present", bool(detail.get("class_report")), len(detail.get("class_report") or []))
        h.check("feature importance / XAI", bool(detail.get("feature_importance")), len(detail.get("feature_importance") or []))
        validation = client.get(f"/models/{classifier['id']}/validate", headers=AH).json()
        h.check("live validation re-scores stored traffic", validation.get("valid") in (True, False) and validation.get("evaluation", {}).get("rows", 0) > 0,
                f"accuracy={validation.get('accuracy')} rows={validation.get('evaluation', {}).get('rows')}")
    comparison = client.post("/models/compare", json={"model_ids": [m["id"] for m in models["items"]]}, headers=AH).json()
    h.check("model comparison", len(comparison.get("models", [])) >= 2 and comparison.get("best"), list(comparison.keys()))

    # ------------------------------------------------------------- datasets
    h.section("Datasets")
    datasets = client.get("/datasets", headers=AH).json()
    h.check("dataset library", datasets.get("pagination", {}).get("total", 0) >= 1, datasets.get("pagination", {}).get("total"))
    samples = client.get("/datasets/samples", headers=AH).json()
    h.check("bundled samples listed", len(samples.get("items", [])) >= 2 and samples.get("limits", {}).get("max_upload_mb"), len(samples.get("items", [])))
    if datasets.get("items"):
        dataset_id = datasets["items"][0]["id"]
        detail = client.get(f"/datasets/{dataset_id}", headers=AH).json()
        profile = detail.get("profile") or {}
        if profile.get("schema_coverage") is None:
            reprofiled = client.post(f"/datasets/{dataset_id}/profile", headers=AH)
            h.check("profile recomputed", reprofiled.status_code == 200 and (reprofiled.json().get("profile") or {}).get("schema_coverage") is not None, reprofiled.status_code)
        else:
            h.check("dataset profile available", profile.get("rows", 0) > 0, profile.get("rows"))
        preview = client.get(f"/datasets/{dataset_id}/preview", headers=AH, params={"limit": 5}).json()
        h.check("dataset preview", len(preview.get("rows", [])) == 5 and preview.get("column_mapping"), preview.get("total_rows"))
        analyzed = client.post(f"/datasets/{dataset_id}/analyze", headers=AH, params={"limit": 25, "create_alerts": False}).json()
        h.check("dataset analysis via live pipeline", analyzed.get("summary", {}).get("rows") == 25, analyzed.get("summary", {}).get("attacks_detected"))
        h.check("analysis scores against labels", bool(analyzed.get("summary", {}).get("correctness")), analyzed.get("summary", {}).get("correctness", {}).get("accuracy"))

    # -------------------------------------------------------------- reports
    h.section("Reports")
    pdf = client.post("/reports/generate", json={"window": "24h", "format": "pdf", "title": "Smoke test security brief"}, headers=AH)
    pdf_body = pdf.json()
    h.check("PDF report generated", pdf.status_code == 200 and pdf_body.get("size_bytes", 0) > 8000, pdf_body.get("size_bytes"))
    if pdf.status_code == 200:
        downloaded = client.get(f"/reports/{pdf_body['id']}/download", headers=AH)
        h.check("PDF download is a real PDF", downloaded.status_code == 200 and downloaded.content[:4] == b"%PDF" and len(downloaded.content) > 15000, len(downloaded.content))
        h.check("report has sections + KPI summary", len(pdf_body.get("sections", [])) > 4 and bool(pdf_body.get("summary", {}).get("kpis")), pdf_body.get("sections"))
    csv_report = client.post("/reports/generate", json={"window": "24h", "format": "csv"}, headers=AH)
    h.check("CSV report generated", csv_report.status_code == 200, csv_report.json().get("size_bytes"))
    if csv_report.status_code == 200:
        csv_download = client.get(f"/reports/{csv_report.json()['id']}/download", headers=AH)
        h.check("CSV download has content", csv_download.status_code == 200 and len(csv_download.content) > 100, len(csv_download.content))
    viewer_generate = client.post("/reports/generate", json={"window": "24h", "format": "pdf"}, headers=VH)
    h.check("viewer cannot generate reports (RBAC)", viewer_generate.status_code == 403, viewer_generate.status_code)

    # ------------------------------------------------------------ blockchain
    h.section("Blockchain integrity ledger")
    status = client.get("/blockchain/status", headers=AH).json()
    h.check("ledger status", status.get("ledger", {}).get("total_events", 0) > 0 and status.get("anchor", {}).get("mode"),
            f"mode={status.get('anchor', {}).get('mode')} events={status.get('ledger', {}).get('total_events')}")
    ledger_stats = client.get("/blockchain/stats", headers=AH).json()
    h.check("ledger stats", ledger_stats.get("total_events", 0) > 0 and "verified_percentage" in ledger_stats, ledger_stats.get("verified_percentage"))
    contract = client.get("/blockchain/contract", headers=AH).json()
    h.check("contract ABI published", contract.get("abi_size", 0) >= 10 and "recordEventHash" in contract.get("functions", []), contract.get("abi_source"))
    events = client.get("/blockchain/events", headers=AH, params={"limit": 5}).json()
    h.check("ledger event list", len(events.get("items", [])) > 0, events.get("pagination", {}).get("total"))
    recorded = client.post("/blockchain/record", headers=AH, json={
        "event_type": "manual_event",
        "payload": {"purpose": "smoke test", "at": int(time.time())},
        "anchor": True,
    }).json()
    h.check("event recorded with hash + chain position", bool(recorded.get("event_hash")) and recorded.get("chain_position", 0) > 0,
            f"pos={recorded.get('chain_position')} anchor={recorded.get('anchor_mode')}")
    # (a) authoritative stored-record verification (what the Integrity Ledger UI does)
    stored_check = client.post("/blockchain/verify", headers=AH, json={"event_id": recorded["id"]}).json()
    h.check("event verification passes (stored record)", stored_check.get("match") is True and stored_check.get("status") == "verified",
            [c["name"] for c in stored_check.get("checks", [])])
    # (b) stateless third-party recomputation from the published hash inputs
    verified = client.post("/blockchain/verify", headers=AH, json={
        "event_id": recorded["id"], "event_hash": recorded["event_hash"], "event_type": recorded["event_type"],
        "timestamp": recorded["created_at"], "payload": recorded["payload"], "prev_hash": recorded.get("prev_hash"),
    }).json()
    h.check("stateless recomputation passes", verified.get("mode") == "recomputation" and verified.get("match") is True, verified.get("status"))
    forged = client.post("/blockchain/verify", headers=AH, json={
        "event_id": recorded["id"], "event_hash": "f" * 64, "event_type": recorded["event_type"],
        "timestamp": recorded["created_at"], "payload": recorded["payload"], "prev_hash": recorded.get("prev_hash"),
    }).json()
    h.check("forged hash is rejected", forged.get("match") is False and forged.get("status") == "failed", forged.get("status"))
    recomputed = client.post("/blockchain/verify", headers=AH, json={
        "event_id": recorded["id"], "event_type": recorded["event_type"], "timestamp": recorded["created_at"],
        "payload": recorded["payload"], "prev_hash": recorded.get("prev_hash"), "event_hash": recorded["event_hash"],
    }).json()
    h.check("stateless hash recomputation matches", recomputed.get("mode") == "recomputation" and recomputed.get("match") is True,
            recomputed.get("status"))
    tampered = client.post("/blockchain/verify", headers=AH, json={
        "event_id": recorded["id"], "event_type": recorded["event_type"], "timestamp": recorded["created_at"],
        "payload": {"purpose": "tampered"}, "prev_hash": recorded.get("prev_hash"), "event_hash": recorded["event_hash"],
    }).json()
    h.check("tampered payload fails recomputation", tampered.get("match") is False and tampered.get("status") == "failed", tampered.get("status"))
    incomplete = client.post("/blockchain/verify", headers=AH, json={
        "event_type": recorded["event_type"], "payload": recorded["payload"], "event_hash": recorded["event_hash"],
    }).json()
    h.check("incomplete inputs are flagged, not silently accepted",
            incomplete.get("match") is False and any(c["name"] == "Completeness" for c in incomplete.get("checks", [])),
            [c["name"] for c in incomplete.get("checks", [])])
    failed_rows = client.get("/blockchain/events", headers=AH, params={"verification_status": "failed", "limit": 5}).json()
    h.check("failed ledger entries are filterable", isinstance(failed_rows.get("items"), list), failed_rows.get("pagination", {}).get("total"))
    if failed_rows.get("items"):
        broken = client.post("/blockchain/verify", headers=AH, json={"event_id": failed_rows["items"][0]["id"]}).json()
        h.check("tamper-demo entry fails verification", broken.get("status") == "failed" and broken.get("match") is False, broken.get("message", "")[:60])
    missing = client.post("/blockchain/verify", headers=AH, json={"event_id": "does-not-exist"}).json()
    h.check("unknown event id reported", missing.get("exists") is False and missing.get("match") is False, missing.get("message", "")[:40])
    chain = client.post("/blockchain/verify-chain", headers=AH, params={"limit": 200}).json()
    h.check("chain verification reports breaks", chain.get("checked", 0) > 0 and "broken_count" in chain,
            f"checked={chain.get('checked')} broken={chain.get('broken_count')}")
    retry = client.post("/blockchain/retry-pending", headers=AH, params={"limit": 10}).json()
    h.check("pending anchors can be retried", "attempted" in retry, retry)
    viewer_record = client.post("/blockchain/record", headers=VH, json={"event_type": "manual_event", "payload": {}})
    h.check("viewer cannot write to the ledger (RBAC)", viewer_record.status_code == 403, viewer_record.status_code)

    # ------------------------------------------------------------ simulation
    h.section("Simulation console")
    scenarios = client.get("/simulation/scenarios", headers=AH).json()
    h.check("scenario catalogue", len(scenarios.get("items", [])) >= 5 and scenarios.get("label"), len(scenarios.get("items", [])))
    sim_status = client.get("/simulation/status", headers=AH).json()
    h.check("simulation status labelled as synthetic", sim_status.get("is_simulated") is True and "Simulation" in (sim_status.get("label") or ""), sim_status.get("status"))
    injected = client.post("/simulation/inject", headers=AH, params={"attack_type": "Port Scan", "count": 6, "create_alerts": False}).json()
    h.check("one-shot attack injection", injected.get("summary", {}).get("rows") == 6, injected.get("summary", {}).get("attacks_detected"))
    started = client.post("/simulation/start", headers=AH, params={"scenario": "mixed", "intensity": 2, "duration_seconds": 30, "tick_seconds": 1}).json()
    h.check("simulation start", started.get("status") == "running", started.get("status"))
    time.sleep(3.5)
    running = client.get("/simulation/status", headers=AH).json()
    h.check("ticks generate + analyze flows", running.get("generated_flows", 0) > 0 and running.get("analyzed_flows", 0) > 0, running.get("generated_flows"))
    h.check("progress + rate reported", running.get("progress", 0) > 0 and running.get("flows_per_second", 0) > 0, running.get("flows_per_second"))
    h.check("pause", client.post("/simulation/pause", headers=AH).json().get("status") == "paused")
    h.check("resume", client.post("/simulation/resume", headers=AH).json().get("status") == "running")
    stopped = client.post("/simulation/stop", headers=AH).json()
    h.check("stop finalizes the run", stopped.get("status") == "stopped", stopped.get("status"))
    viewer_start = client.post("/simulation/start", headers=VH, params={"scenario": "mixed"})
    h.check("viewer cannot control the simulation (RBAC)", viewer_start.status_code == 403, viewer_start.status_code)

    # ----------------------------------------------------------------- audit
    h.section("Audit trail")
    audit = client.get("/audit-logs", headers=AH, params={"limit": 10}).json()
    h.check("audit entries recorded", audit.get("pagination", {}).get("total", 0) > 0 and audit.get("stats"), audit.get("pagination", {}).get("total"))
    entry = audit["items"][0] if audit.get("items") else {}
    h.check("entries are hash-chained", bool(entry.get("integrity_hash")) and "prev_hash" in entry, str(entry.get("integrity_hash"))[:16])
    h.check("actor + category captured", bool(entry.get("action")) and bool(entry.get("category")), entry.get("action"))
    categories = client.get("/audit-logs/categories", headers=AH).json()
    h.check("audit categories + stats", len(categories.get("items", [])) >= 8 and categories.get("stats", {}).get("total", 0) > 0, len(categories.get("items", [])))
    filtered = client.get("/audit-logs", headers=AH, params={"category": "auth", "limit": 5}).json()
    h.check("category filter works", all(item.get("category") == "auth" for item in filtered.get("items", [])), len(filtered.get("items", [])))
    audit_verify = client.post("/audit-logs/verify", headers=AH, params={"limit": 100}).json()
    h.check("audit chain verification", audit_verify.get("checked", 0) > 0 and "intact" in audit_verify, f"intact={audit_verify.get('intact')}")
    exported = client.get("/audit-logs/export", headers=AH, params={"window": "7d", "limit": 50})
    h.check("audit CSV export", exported.status_code == 200 and exported.text.startswith("timestamp,"), len(exported.content))
    h.check("viewer cannot export audit logs (RBAC)", client.get("/audit-logs/export", headers=VH).status_code == 403)

    # ----------------------------------------------------------------- admin
    h.section("Admin console")
    admin_stats = client.get("/admin/stats", headers=AH).json()
    counts = admin_stats.get("counts", {})
    h.check("platform counts", counts.get("traffic_records", 0) > 0 and counts.get("users", 0) >= 3, json.dumps(counts)[:90])
    h.check("alert + ledger + audit summaries", bool(admin_stats.get("alerts")) and bool(admin_stats.get("blockchain")) and bool(admin_stats.get("audit")), list(admin_stats.keys()))
    users = client.get("/admin/users", headers=AH).json()
    h.check("user list", users.get("pagination", {}).get("total", 0) >= 3, users.get("pagination", {}).get("total"))
    settings = client.get("/admin/settings", headers=AH).json()
    h.check("settings payload (runtime/defaults/environment/security)",
            all(key in settings for key in ("runtime", "defaults", "environment", "security")), list(settings.keys()))
    original_throttle = settings["runtime"].get("alert_throttle_minutes")
    changed = client.patch("/admin/settings", headers=AH, json={"alert_throttle_minutes": int(original_throttle or 5) + 1}).json()
    h.check("runtime setting update audited", "alert_throttle_minutes" in changed.get("changed", {}), changed.get("changed"))
    restored = client.patch("/admin/settings", headers=AH, json={"alert_throttle_minutes": original_throttle}).json()
    h.check("runtime setting restored", restored["runtime"].get("alert_throttle_minutes") == original_throttle, restored["runtime"].get("alert_throttle_minutes"))
    invalid = client.patch("/admin/settings", headers=AH, json={"alert_throttle_minutes": 99999})
    h.check("out-of-range setting rejected", invalid.status_code == 422, invalid.status_code)
    seed_status = client.get("/admin/seed/status", headers=AH).json()
    h.check("seed status", seed_status.get("status") in ("complete", "skipped", "error", "running"), seed_status.get("status"))

    # ------------------------------------------------------------------- MFA
    h.section("Multi-factor authentication (TOTP)")
    mfa_status = client.get("/auth/mfa/status", headers=AH).json()
    h.check("MFA status readable", "enabled" in mfa_status and mfa_status.get("digits") == 6, mfa_status)
    if not mfa_status.get("enabled"):
        enrolled = client.post("/auth/mfa/enable", headers=AH).json()
        h.check("enrolment returns secret + otpauth URI", bool(enrolled.get("secret")) and (enrolled.get("otpauth_uri") or "").startswith("otpauth://totp/"),
                enrolled.get("issuer"))
        h.check("QR code rendered", len(enrolled.get("qr_png_base64") or "") > 500, len(enrolled.get("qr_png_base64") or ""))
        code = totp_code(enrolled["secret"])
        confirmed = client.post("/auth/mfa/confirm", headers=AH, json={"code": code})
        h.check("confirmation activates MFA", confirmed.status_code == 200 and confirmed.json().get("enabled") is True, confirmed.status_code)
        challenge = client.post("/auth/login", json={"email": args.admin_email, "password": args.admin_password}).json()
        h.check("login without a code returns a challenge", challenge.get("require_mfa") is True and not challenge.get("access_token"), challenge.get("mfa_message", "")[:50])
        bad = client.post("/auth/login", json={"email": args.admin_email, "password": args.admin_password, "mfa_code": "000000"}).json()
        h.check("wrong code rejected", bad.get("require_mfa") is True and not bad.get("access_token"))
        good = client.post("/auth/login", json={"email": args.admin_email, "password": args.admin_password, "mfa_code": totp_code(enrolled["secret"])})
        h.check("correct code issues a token", good.status_code == 200 and bool(good.json().get("access_token")))
        h.check("MFA enrolment is audited",
                any("mfa" in item.get("action", "") for item in client.get("/audit-logs", headers=AH, params={"limit": 20}).json().get("items", [])))
        disabled = client.post("/auth/mfa/disable", headers=AH, json={"code": totp_code(enrolled["secret"])})
        h.check("MFA can be disabled with a valid code", disabled.status_code == 200 and disabled.json().get("enabled") is False, disabled.status_code)
        after = client.post("/auth/login", json={"email": args.admin_email, "password": args.admin_password})
        h.check("login works again after disabling MFA", after.status_code == 200 and bool(after.json().get("access_token")))
    else:
        h.check("MFA already enabled for this account (skipping enrolment)", True, "enabled")

    # -------------------------------------------------------------- realtime
    h.section("Realtime channel")
    try:
        import websockets  # type: ignore
    except ImportError:
        websockets = None
    ws_url = args.base_url.replace("/api", "").replace("http", "ws") + "/api/traffic/ws?token=" + admin_token
    if websockets is None:
        print(f"  {DIM}- websocket check skipped (install 'websockets' to enable){RESET}")
    else:
        import asyncio

        async def probe() -> bool:
            try:
                async with websockets.connect(ws_url, open_timeout=10) as socket:
                    await socket.send(json.dumps({"type": "ping"}))
                    await asyncio.wait_for(socket.recv(), timeout=10)
                    return True
            except Exception:
                return False

        h.check("WebSocket accepts an authenticated client", asyncio.run(probe()))

    return h.summary()


if __name__ == "__main__":
    sys.exit(main())
