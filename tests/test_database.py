from sqlalchemy.orm import Session  # Ajouter cet import
from app.models.scan import ScanResult

def test_save_and_retrieve_scan(db_session: Session):
    scan = ScanResult(
        url="http://vuln-db.com",
        status="Completed",
        vulnerabilities=[{"type": "SQLi", "payload": "' OR 1=1 --"}]  # Supprimer 'type=' et 'payload=' du constructeur
    )
    # ... (le reste du code)