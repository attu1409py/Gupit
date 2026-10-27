"""Smoke tests for API health and metadata endpoints."""

from fastapi.testclient import TestClient


def test_health_check_endpoint(client: TestClient):
    """Verify that GET /api/health responds with 200 OK and valid health metadata."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "Gupit"
    assert data["version"] == "0.1.0"
    assert "storage_backend" in data


def test_root_endpoint(client: TestClient):
    """Verify that GET / returns app metadata and link to health check."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["app"] == "Gupit"
    assert data["status"] == "operational"
    assert data["health_check"] == "/api/health"
