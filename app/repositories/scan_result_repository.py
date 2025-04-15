from sqlalchemy.orm import Session
from app.models.scan import ScanResult

class ScanResultRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, scan_data: dict) -> ScanResult:
        scan = ScanResult(**scan_data)
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def get_by_id(self, scan_id: int) -> ScanResult:
        return self.db.query(ScanResult).get(scan_id)