from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_scan_endpoint():
    response = client.post("/scan/", json={"url": "http://example.com"})
    assert response.status_code == 200
