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
