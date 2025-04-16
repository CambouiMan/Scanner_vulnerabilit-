import json
from fastapi.testclient import TestClient
from unittest.mock import patch
from app.core.database import  Database
from main import app
client = TestClient(app)

@patch("app.services.scanner.Scanner.scan")
def test_end_to_end_scan(mock_scan):
    # Simule un résultat de scan
    mock_scan.return_value = [{"type": "xss"}]

    # Envoie la requête de scan
    response = client.post("/scan/", params={"url": "http://test.com"})
    assert response.status_code == 200

    data = response.json()
    assert "scan_id" in data
    assert "results" in data

    # Vérifie que le résultat contient bien du XSS
    assert any("xss" in str(r).lower() for r in data["results"])