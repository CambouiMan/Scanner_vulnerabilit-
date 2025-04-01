from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from app.core.database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    status = Column(String, default="Completed")
    vulnerabilities = Column(String, default="[]")  # Stockage JSON sous forme de string
    timestamp = Column(DateTime, default=datetime.utcnow)
