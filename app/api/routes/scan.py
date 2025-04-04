from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.database import SessionLocal, engine , ScanResult
from app.models.scan import ScanResult, Base
from app.services.scanner import Scanner

# Création du router FastAPI
router = APIRouter()

# Initialisation de la base de données
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
def save_scan_result(url, vulnerability_type, payload, status):
    db = SessionLocal()
    result = ScanResult(url=url, vulnerability_type=vulnerability_type, payload=payload, status=status)
    db.add(result)
    db.commit()
    db.close()

@router.post("/")
def start_scan(url: str, db: Session = Depends(get_db)):
    scanner = Scanner()
    results = scanner.scan(url)
    
    # Stockage des résultats en base de données
    scan_entry = ScanResult(url=url, status="Completed", vulnerabilities=str(results))
    db.add(scan_entry)
    db.commit()
    db.refresh(scan_entry)
    
    return {"message": "Scan terminé", "scan_id": scan_entry.id, "results": results}
