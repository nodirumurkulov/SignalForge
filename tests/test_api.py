import importlib

from fastapi.testclient import TestClient

from app.main import app, store


def test_api_intake_and_export() -> None:
    store.clear()
    client = TestClient(app)

    response = client.post(
        "/api/intake",
        json={
            "source_name": "api-test",
            "text": "Indicator hxxp://secure-login.example-attacker.net/path and 8.8.8.8",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["extracted_count"] >= 2
    assert body["clusters"]

    export_response = client.post("/api/export", json={"format": "splunk"})

    assert export_response.status_code == 200
    assert "index=*" in export_response.json()["content"]


def test_security_headers_are_applied() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_api_config_reports_docs_enabled() -> None:
    client = TestClient(app)

    response = client.get("/api/config")

    assert response.status_code == 200
    assert response.json() == {"docs_enabled": True, "docs_url": "/docs"}


def test_api_config_reports_docs_disabled(monkeypatch) -> None:
    monkeypatch.setenv("TIFP_ENABLE_DOCS", "false")

    import app.main as main

    reloaded_main = importlib.reload(main)
    client = TestClient(reloaded_main.app)

    response = client.get("/api/config")
    docs_response = client.get("/docs")

    assert response.status_code == 200
    assert response.json() == {"docs_enabled": False, "docs_url": None}
    assert docs_response.status_code == 404

    monkeypatch.delenv("TIFP_ENABLE_DOCS")
    importlib.reload(main)


def test_oversized_request_body_is_rejected() -> None:
    client = TestClient(app)

    response = client.post(
        "/api/intake",
        content='{"source_name":"api-test","text":"x"}',
        headers={"Content-Type": "application/json", "Content-Length": "1000001"},
    )

    assert response.status_code == 413
