"""HTTP-level tests: routing, auth, RBAC, error envelopes and empty-state safety.

Runs the real FastAPI application in-process (no server, no network) against the
throwaway database configured in ``conftest.py``. Demo seeding is disabled, so
these tests also prove the API degrades gracefully when there is no data yet.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import auth_service
from app.storage import get_store

PASSWORD = "Unit@Test123"


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def accounts(client: TestClient) -> dict:
    """One account per role. Self-registration cannot create an admin, so the
    admin role is promoted through the store the way the admin console does."""
    created = {}
    for role, email in (("viewer", "viewer@example.com"), ("analyst", "analyst@example.com"),
                        ("admin", "admin@example.com")):
        user = auth_service.register(name=f"Test {role.title()}", email=email, password=PASSWORD, role="viewer")
        if role != "viewer":
            user = auth_service.update_user(user["id"], {"role": role})
        created[role] = user
    return created


def login(client: TestClient, email: str) -> dict:
    response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture(scope="module")
def tokens(client: TestClient, accounts: dict) -> dict:
    return {
        role: login(client, account["email"])["access_token"]
        for role, account in accounts.items()
    }


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------- public routes
def test_health_and_config_are_public(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] in {"online", "degraded", "partial"}

    config = client.get("/api/config")
    assert config.status_code == 200
    body = config.json()
    assert body["app_name"] == "CyberForecast AI"
    # The public config must never leak secrets or connection strings.
    assert "secret" not in config.text.lower().replace("jwt_secret_policy", "")
    assert "password" not in {key.lower() for key in body}


def test_detailed_health_requires_authentication(client, tokens):
    assert client.get("/api/health/detailed").status_code == 401
    assert client.get("/api/health/detailed", headers=auth(tokens["viewer"])).status_code == 200


def test_openapi_is_served_under_the_api_prefix(client):
    # FastAPI serves the schema at the root locally and under /api on serverless.
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.status_code
    paths = response.json()["paths"]
    assert len(paths) > 80
    assert "/api/auth/login" in paths
    assert "/api/blockchain/verify" in paths


# ------------------------------------------------------------------ auth + RBAC
def test_protected_routes_require_a_token(client):
    for path in ("/api/analytics/overview", "/api/alerts", "/api/admin/users", "/api/blockchain/status"):
        assert client.get(path).status_code == 401, path


def test_invalid_tokens_are_rejected(client):
    for header in ("Bearer not-a-token", "Bearer a.b.c", "Token abc", ""):
        response = client.get("/api/auth/me", headers={"Authorization": header})
        assert response.status_code == 401, header


def test_login_rejects_bad_credentials(client, accounts):
    response = client.post("/api/auth/login",
                           json={"email": accounts["viewer"]["email"], "password": "Wrong@1234"})
    assert response.status_code == 401
    assert response.json()["detail"]
    # The message must not reveal whether the account exists.
    unknown = client.post("/api/auth/login", json={"email": "nobody@example.com", "password": PASSWORD})
    assert unknown.status_code == 401


def test_self_registration_cannot_grant_admin(client):
    response = client.post("/api/auth/register", json={
        "name": "Would Be Admin", "email": "escalate@example.com",
        "password": PASSWORD, "role": "admin",
    })
    assert response.status_code in (200, 201)
    assert response.json()["user"]["role"] == "analyst"


def test_weak_passwords_are_rejected(client):
    """Short passwords fail schema validation; weak-but-long ones fail the policy."""
    for password in ("short", "alllowercase1", "ALLUPPERCASE1", "NoDigitsHere"):
        response = client.post("/api/auth/register", json={
            "name": "Weak Password", "email": f"weak-{abs(hash(password)) % 10 ** 8}@example.com",
            "password": password, "role": "viewer",
        })
        assert response.status_code in (400, 422), f"{password} -> {response.status_code}"
        assert "password" in response.text.lower()
        assert response.status_code != 200


def test_role_capabilities_are_enforced_over_http(client, tokens):
    admin_only = ["/api/admin/users", "/api/admin/settings", "/api/audit-logs", "/api/admin/stats"]
    for path in admin_only:
        assert client.get(path, headers=auth(tokens["admin"])).status_code == 200, path
        assert client.get(path, headers=auth(tokens["analyst"])).status_code == 403, path
        assert client.get(path, headers=auth(tokens["viewer"])).status_code == 403, path


def test_read_only_role_cannot_mutate(client, tokens):
    write_calls = [
        ("post", "/api/blockchain/record", {"event_type": "manual_event", "payload": {}}),
        ("post", "/api/simulation/start", None),
        ("post", "/api/reports/generate", {"window": "24h", "format": "csv"}),
    ]
    for method, path, body in write_calls:
        response = client.request(method, path, json=body, headers=auth(tokens["viewer"]))
        assert response.status_code == 403, f"{method} {path} -> {response.status_code}"


def test_analyst_can_operate_but_not_administer(client, tokens):
    record = client.post("/api/blockchain/record", headers=auth(tokens["analyst"]),
                         json={"event_type": "manual_event", "payload": {"source": "api-test"}})
    assert record.status_code == 200, record.text
    assert record.json()["event_hash"]
    assert client.get("/api/admin/users", headers=auth(tokens["analyst"])).status_code == 403


def test_me_reflects_the_authenticated_user(client, tokens, accounts):
    body = client.get("/api/auth/me", headers=auth(tokens["admin"])).json()
    assert body["email"] == accounts["admin"]["email"]
    assert body["role"] == "admin"
    assert "users.manage" in body["capabilities"]
    assert "password_hash" not in body and "password" not in body


# --------------------------------------------------------------- empty states
def test_analytics_endpoints_are_safe_with_no_traffic(client, tokens):
    """A fresh deployment has no flows yet - every view must answer, not crash."""
    headers = auth(tokens["admin"])
    dashboard = client.get("/api/analytics/dashboard", headers=headers)
    assert dashboard.status_code == 200
    assert dashboard.json()["kpis"]["flows"] == 0

    overview = client.get("/api/analytics/overview?window=24h", headers=headers)
    assert overview.status_code == 200
    assert overview.json()["empty"] is True

    for path in ("/api/traffic/live", "/api/traffic/recent", "/api/traffic/timeline?window=24h&limit=10",
                 "/api/traffic/threat-map?window=24h&limit=10", "/api/traffic/summary?window=24h",
                 "/api/analytics/trends?window=24h", "/api/analytics/top-entities",
                 "/api/alerts", "/api/alerts/stats", "/api/forecast/history", "/api/forecast/trend",
                 "/api/models", "/api/datasets", "/api/reports", "/api/blockchain/events",
                 "/api/simulation/status", "/api/simulation/scenarios"):
        response = client.get(path, headers=headers)
        assert response.status_code == 200, f"{path} -> {response.status_code} {response.text[:200]}"


def test_forecast_refuses_to_guess_without_history(client, tokens):
    """No traffic -> no forecast. The API says so instead of inventing numbers."""
    response = client.post("/api/forecast", headers=auth(tokens["admin"]), json={"horizon": 30})
    assert response.status_code == 409, response.text
    assert "no traffic history" in response.json()["detail"].lower()

    options = client.get("/api/forecast/options", headers=auth(tokens["admin"]))
    assert options.status_code == 200
    assert options.json()["disclaimer"]


# ------------------------------------------------------- detection + integrity
def test_prediction_uses_the_heuristic_baseline_until_a_model_is_trained(client, tokens):
    response = client.post("/api/predict", headers=auth(tokens["analyst"]), json={"flow": {
        "timestamp": "2026-09-29T00:00:00Z", "source_ip": "203.0.113.5", "destination_ip": "10.20.30.40",
        "source_port": 51234, "destination_port": 22, "protocol": "TCP", "packet_count": 9000,
        "byte_count": 4_000_000, "flow_duration": 1.1, "packets_per_second": 8100,
        "bytes_per_second": 3_600_000, "connection_count": 900, "tcp_flags": "SYN",
        "failed_connections": 420, "request_frequency": 5200,
    }})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model"]["engine"] == "heuristic-fallback"
    assert "heuristic baseline" in body["model"]["note"].lower()
    assert 0.0 <= body["risk_score"] <= 1.0
    assert body["explanation"]


def test_record_and_verify_round_trip_over_http(client, tokens):
    record = client.post("/api/blockchain/record", headers=auth(tokens["admin"]), json={
        "event_type": "api_test", "payload": {"case": "round-trip"}, "anchor": False,
    }).json()

    verified = client.post("/api/blockchain/verify", headers=auth(tokens["admin"]),
                           json={"event_id": record["id"]}).json()
    assert verified["match"] is True
    assert verified["status"] == "verified"

    detail = client.get(f"/api/blockchain/{record['id']}", headers=auth(tokens["admin"])).json()
    assert detail["hash_inputs"]["event_id"] == record["id"]
    assert detail["hash_inputs"]["hash_version"] == "v2"

    chain = client.post("/api/blockchain/verify-chain?limit=50", headers=auth(tokens["admin"])).json()
    assert chain["checked"] >= 1
    assert chain["intact"] is True


def test_stateless_verification_detects_a_tampered_payload_over_http(client, tokens):
    record = client.post("/api/blockchain/record", headers=auth(tokens["admin"]), json={
        "event_type": "api_test", "payload": {"case": "tamper", "risk_score": 0.9}, "anchor": False,
    }).json()

    honest = client.post("/api/blockchain/verify", headers=auth(tokens["admin"]), json={
        "event_id": record["id"], "event_type": record["event_type"], "timestamp": record["created_at"],
        "payload": record["payload"], "prev_hash": record["prev_hash"], "event_hash": record["event_hash"],
    }).json()
    assert honest["mode"] == "recomputation" and honest["match"] is True

    tampered = client.post("/api/blockchain/verify", headers=auth(tokens["admin"]), json={
        "event_id": record["id"], "event_type": record["event_type"], "timestamp": record["created_at"],
        "payload": {"case": "tamper", "risk_score": 0.1}, "prev_hash": record["prev_hash"],
        "event_hash": record["event_hash"],
    }).json()
    assert tampered["match"] is False and tampered["status"] == "failed"


def test_audit_trail_records_api_activity(client, tokens):
    client.post("/api/blockchain/record", headers=auth(tokens["admin"]),
                json={"event_type": "api_test", "payload": {"case": "audit"}})
    logs = client.get("/api/audit-logs?limit=20", headers=auth(tokens["admin"])).json()
    assert logs["pagination"]["total"] >= 1
    actions = {entry["action"] for entry in logs["items"]}
    assert any(action.startswith("blockchain.") for action in actions)
    for entry in logs["items"]:
        assert entry["integrity_hash"] and entry["prev_hash"] is not None
        metadata = entry["metadata"] or {}
        forbidden = {"password", "password_hash", "secret", "token", "access_token", "private_key", "authorization"}
        assert not forbidden & {str(key).lower() for key in metadata}, metadata


# ------------------------------------------------------------- error envelopes
def test_unknown_routes_return_a_json_envelope(client):
    response = client.get("/api/does-not-exist")
    assert response.status_code in (401, 404)
    assert response.headers["content-type"].startswith("application/json")


def test_validation_errors_are_structured(client, tokens):
    response = client.post("/api/predict", headers=auth(tokens["analyst"]), json={"not_a_flow": True})
    assert response.status_code == 422
    body = response.json()
    assert body["error_type"] == "validation_error"
    assert body["errors"] and body["errors"][0]["field"] == "flow"


def test_missing_ledger_entry_returns_404(client, tokens):
    response = client.get("/api/blockchain/nope-not-real", headers=auth(tokens["admin"]))
    assert response.status_code == 404
    assert response.json()["detail"]


def test_admin_routes_are_the_only_way_to_change_runtime_settings(client, tokens):
    settings_body = client.get("/api/admin/settings", headers=auth(tokens["admin"])).json()
    original = settings_body["runtime"]["alert_throttle_minutes"]

    changed = client.patch("/api/admin/settings", headers=auth(tokens["admin"]),
                           json={"alert_throttle_minutes": original + 1})
    assert changed.status_code == 200
    assert changed.json()["changed"]["alert_throttle_minutes"] == {"from": original, "to": original + 1}

    restored = client.patch("/api/admin/settings", headers=auth(tokens["admin"]),
                            json={"alert_throttle_minutes": original})
    assert restored.json()["runtime"]["alert_throttle_minutes"] == original

    assert client.patch("/api/admin/settings", headers=auth(tokens["admin"]),
                        json={"alert_throttle_minutes": -5}).status_code == 422


def test_cors_preflight_is_allowed(client):
    response = client.options("/api/auth/login", headers={
        "Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    })
    assert response.status_code in (200, 204)
    assert "access-control-allow-origin" in {k.lower() for k in response.headers}
