import sys
from pathlib import Path

import pytest

# Add the project root to Python's import path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client


def test_home(client):
    response = client.get("/")
    assert response.status_code == 200


def test_system_status(client):
    response = client.get("/api/system-status")

    assert response.status_code == 200

    data = response.get_json()

    assert "backend" in data
    assert "database" in data
    assert data["backend"] == "UP"


def test_get_websites(client):
    response = client.get("/api/websites")

    assert response.status_code == 200
    assert isinstance(response.get_json(), list)


def test_get_settings(client):
    response = client.get("/api/settings")

    assert response.status_code == 200

    data = response.get_json()

    assert "monitoring_enabled" in data
    assert "monitoring_interval_minutes" in data
    assert "max_retries" in data


def test_get_incidents(client):
    response = client.get("/api/incidents")

    assert response.status_code == 200
    assert isinstance(response.get_json(), list)


def test_monitoring_status(client):
    response = client.get("/api/monitoring/status")

    assert response.status_code == 200

    data = response.get_json()

    assert "monitoring_enabled" in data
    assert "monitoring_interval_minutes" in data
    assert "max_retries" in data