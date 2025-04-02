from fastapi.testclient import TestClient
from app.api.routes.scan import router
from app.core.database import SessionLocal, Base, engine
from app.models.scan import ScanResult
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch
from main import app  # Assurez-vous que votre fichier `main.py` contient bien `app`

# Configuration de la base de données pour les tests
Base.metadata.create_all(bind=engine)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides["get_db"] = override_get_db
client = TestClient(app)

@patch("app.services.scanner.Scanner.scan", return_value=[{"type": "XSS", "url": "http://example.com", "status": "Vulnerable"}])
def test_start_scan(mock_scan):
    response = client.post("/scan/", params={"url": "http://example.com"})
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["message"] == "Scan terminé"
    assert "scan_id" in json_response
    assert json_response["results"] == [{"type": "XSS", "url": "http://example.com", "status": "Vulnerable"}]
