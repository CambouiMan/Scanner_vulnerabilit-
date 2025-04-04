from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Définition de l'URL de la base de données SQLite
DATABASE_URL = "sqlite:///./scanner.db"

# Création du moteur SQLAlchemy
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Session pour interagir avec la base
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base de données ORM
Base = declarative_base()

# Définition de la table des résultats de scan
class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    vulnerability_type = Column(String)
    payload = Column(String, nullable=True)
    status = Column(String)

# Création des tables si elles n'existent pas
def init_db():
    Base.metadata.create_all(bind=engine)
