from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.scan import ScanResult
from fastapi.testclient import TestClient
from app.core.database import SessionLocal
from fastapi import FastAPI


app = FastAPI()
router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/{scan_id}")
def get_results(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan.id, "url": scan.url, "status": scan.status, "vulnerabilities": scan.vulnerabilities, "timestamp": scan.timestamp}

# Tests unitaires
client = TestClient(app)

def test_scan_creation():
    response = client.post("/scan/", json={"url": "http://example.com"})
    assert response.status_code == 200
    assert "scan_id" in response.json()

def test_get_scan_results():
    scan_id = 1  # Supposons qu'un scan existe déjà
    response = client.get(f"/results/{scan_id}")
    assert response.status_code in [200, 404]
