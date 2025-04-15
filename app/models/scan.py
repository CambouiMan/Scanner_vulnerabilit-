from sqlalchemy import Column, Integer, String, DateTime, JSON
from datetime import datetime , timezone
from app.core.database import Database
from sqlalchemy.orm import validates

Base = Database().Base  # Récupération de la Base via le Singleton

class ScanResult(Base):
    __tablename__ = "scan_results"
    __table_args__ = {'extend_existing': True}  # Ajout pour éviter la redéfinition
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False, index=True)
    status = Column(String(50), default="pending")  # pending/completed/failed
    vulnerabilities = Column(JSON, default=[])  # Stockage natif JSON pour PostgreSQL
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # Correction clé ici

    def __repr__(self):
        return f"<ScanResult(id={self.id}, url={self.url}, status={self.status})>"
    def getID(self) : 
        return self.id
    @validates("url")
    def validate_url_length(self, key, url):
        if len(url) > 500:
            raise ValueError("URL exceeds 500 characters limit")
        return url