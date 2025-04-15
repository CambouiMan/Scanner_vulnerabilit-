from app.core.database import Database
from app.models.scan import ScanResult
import pytest

def test_create_scan_result():
    db = Database().SessionLocal()
    scan = ScanResult(
        url="http://test.com",
        status="completed",
        vulnerabilities=[{"type": "XSS"}]
    )
    db.add(scan)
    db.commit()
    
    assert scan.id is not None
    assert scan.timestamp is not None
    db.delete(scan)
    db.commit()
