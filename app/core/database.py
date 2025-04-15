from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from sqlalchemy import create_engine
import os

os.environ["SQLALCHEMY_SILENCE_UBER_WARNING"] = "1"

class Database:
    _instance = None  # Stocke l'instance unique
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.engine = create_engine(
                "sqlite:///./scanner.db",
                connect_args={"check_same_thread": False},
                future=True  # Mode 2.0
            )
            cls._instance.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=cls._instance.engine,
                future=True  # Session compatible 2.0
            )
            cls._instance.Base = declarative_base()
        return cls._instance

    def init_db(self):
        """Crée les tables si elles n'existent pas"""
        self.Base.metadata.create_all(bind=self.engine)

# Déclaration du Singleton
Database()  # Initialisation au chargement du module

# Classe modèle (reste inchangée)
class ScanResult(Database().Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    vulnerability_type = Column(String)
    payload = Column(String, nullable=True)
    status = Column(String)