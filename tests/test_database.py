import pytest
from sqlalchemy import inspect
from sqlalchemy.orm import Session ,sessionmaker
from app.core.database  import Database, ScanResult
from sqlalchemy import create_engine

def test_singleton_pattern():
    """Vérifie que le Singleton fonctionne correctement"""
    db1 = Database()
    db2 = Database()
    assert db1 is db2, "Les instances devraient être identiques (Singleton)"

def test_database_initialization():
    """Teste la création des tables dans la base de données"""
    # Réinitialisation pour un test propre
    Database._instance = None
    db = Database()
    db.init_db()
    
    inspector = inspect(db.engine)
    assert inspector.has_table("scan_results"), "La table 'scan_results' devrait être créée"
   