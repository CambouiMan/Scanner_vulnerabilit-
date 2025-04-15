from fastapi.testclient import TestClient
from main import app
from app.core.database import Database
import pytest

client = TestClient(app)
db = Database()

@pytest.fixture(autouse=True)
def cleanup_db():
    """Nettoie la base après chaque test"""
    yield
    with db.SessionLocal() as session:
        session.query(db.Base.classes.scan_results).delete()
        session.commit()

def test_start_scan_success():
    response = client.post("/scan/", params={"url": "http://example.com"})
    assert response.status_code == 200
    assert "scan_id" in response.json()

def test_start_scan_missing_url():
    response = client.post("/scan/")
    assert response.status_code == 422  # Validation error

def test_get_results_not_found():
    response = client.get("/results/999")
    assert response.status_code == 404

def test_get_all_results():
    # Crée un scan d'abord
    client.post("/scan/", params={"url": "http://test.com"})
    
    response = client.get("/results/")
    assert response.status_code == 200
    assert len(response.json()) > 0