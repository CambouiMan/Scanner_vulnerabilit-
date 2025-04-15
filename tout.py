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

@router.get("/results/{scan_id}")
def get_results(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan.id, "url": scan.url, "status": scan.status, "vulnerabilities": scan.vulnerabilities, "timestamp": scan.timestamp}


@router.get("/results")
def get_scan_results(db: Session = Depends(get_db)):
    return db.query(ScanResult).all()
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

from sqlalchemy import Column, Integer, String, DateTime, JSON
from datetime import datetime
from app.core.database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"
    __table_args__ = {'extend_existing': True}  # Ajout pour éviter la redéfinition
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False, index=True)
    status = Column(String(50), default="pending")  # pending/completed/failed
    vulnerabilities = Column(JSON, default=[])  # Stockage natif JSON pour PostgreSQL
    timestamp = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ScanResult(id={self.id}, url={self.url}, status={self.status})>"
    
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    @abstractmethod
    def scan(self, url: str):
        pass

import requests
import os
import urllib.parse
from app.services.strategies.base import BaseScanner

class SQLiScanner(BaseScanner):
    def __init__(self, payload_file="app/payloads/sqli_payloads.txt"):
        self.payloads = self.load_payloads(payload_file)

    def load_payloads(self, file_path):
        """Charge les payloads SQLi depuis un fichier externe"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"⚠️ Fichier {file_path} introuvable. Utilisation d'un payload par défaut.")
            return ["' OR '1'='1"]  # Payload par défaut

    def scan(self, url: str):
        """Teste les injections SQL sur l'URL fournie"""
        vulnerabilities = []
        sql_errors = [
            "you have an error in your sql syntax", 
            "warning: mysql", 
            "unclosed quotation mark after the character string",
            "sql error"
        ]

        for payload in self.payloads:
            encoded_payload = urllib.parse.quote(payload)  # Encodage pour éviter les erreurs
            full_url = f"{url}?q={encoded_payload}"

            try:
                response = requests.get(full_url, timeout=5)

                # Vérifie si la page renvoie une erreur SQL spécifique
                if any(error in response.text.lower() for error in sql_errors):
                    vulnerabilities.append({
                        "type": "SQLi",
                        "url": url,
                        "payload": payload,
                        "status": "Vulnerable"
                    })

            except requests.RequestException:
                print(f"⚠️ Erreur lors de la requête vers {full_url}")

        return vulnerabilities if vulnerabilities else [{"type": "SQLi", "url": url, "status": "Safe"}]

import requests
import os
import urllib.parse
from app.services.strategies.base import BaseScanner

class XSSScanner(BaseScanner):
    def __init__(self, payload_file="app/payloads/xss_payloads.txt"):
        self.payloads = self.load_payloads(payload_file)

    def load_payloads(self, file_path):
        """Charge les payloads XSS depuis un fichier externe"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"⚠️ Fichier {file_path} introuvable. Utilisation d'un payload par défaut.")
            return ["<script>alert('XSS')</script>"]  # Payload par défaut

    def scan(self, url: str):
        """Teste les injections XSS sur l'URL fournie"""
        vulnerabilities = []
        for payload in self.payloads:
            encoded_payload = urllib.parse.quote(payload)  # Encodage pour éviter les erreurs
            response = requests.get(f"{url}?q={encoded_payload}")

            if payload in response.text:  # Vérifie si la réponse contient le payload injecté
                vulnerabilities.append({
                    "type": "XSS",
                    "url": url,
                    "payload": payload,
                    "status": "Vulnerable"
                })

        return vulnerabilities if vulnerabilities else [{"type": "XSS", "url": url, "status": "Safe"}]

from app.services.strategies.xss import XSSScanner
from app.services.strategies.sqli import SQLiScanner
from app.services.strategies.base import BaseScanner

class ScannerFactory:
    @staticmethod
    def create_scanner(scanner_type: str) -> BaseScanner:
        """Factory pour créer des scanners dynamiquement."""
        scanners = {
            "xss": XSSScanner,
            "sqli": SQLiScanner
        }
        if scanner_type not in scanners:
            raise ValueError(f"Scanner non supporté : {scanner_type}")
        return scanners[scanner_type]()
    
from app.services.strategies.xss import XSSScanner
from app.services.strategies.sqli import SQLiScanner
from app.services.scanner_factory import ScannerFactory

class Scanner:
    def __init__(self):
                # Récupère tous les scanners disponibles via la Factory
        self.scanners = [
            ScannerFactory.create_scanner("xss"),
            ScannerFactory.create_scanner("sqli")
        ]

    def scan(self, url: str):
        results = []
        for scanner in self.scanners:
            results.append(scanner.scan(url))
        return results

from fastapi.testclient import TestClient
from app.api.routes.scan import router
from app.core.database import SessionLocal, Base, engine
from app.models.scan import ScanResult
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch
from main import app  # Assurez-vous que votre fichier `main.py` contient bien `app`

# Configuration de la base de données pour les tests
Base.metadata.create_all(bind=engine)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides["get_db"] = override_get_db
client = TestClient(app)

@patch("app.services.scanner.Scanner.scan", return_value=[{"type": "XSS", "url": "http://example.com", "status": "Vulnerable"}])
def test_start_scan(mock_scan):
    response = client.post("/scan/", params={"url": "http://example.com"})
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["message"] == "Scan terminé"
    assert "scan_id" in json_response
    assert json_response["results"] == [{"type": "XSS", "url": "http://example.com", "status": "Vulnerable"}]

from sqlalchemy.orm import Session  # Ajouter cet import
from app.models.scan import ScanResult

def test_save_and_retrieve_scan(db_session: Session):
    scan = ScanResult(
        url="http://vuln-db.com",
        status="Completed",
        vulnerabilities=[{"type": "SQLi", "payload": "' OR 1=1 --"}]  
    )

# tests/test_scanner.py
import pytest
from unittest.mock import Mock, patch
from app.services.scanner import Scanner
from app.services.strategies.xss import XSSScanner
from app.services.strategies.sqli import SQLiScanner

class TestScanner:
    @pytest.fixture
    def mock_scanners(self):
        # Crée des mocks pour les scanners
        xss_mock = Mock(spec=XSSScanner)
        sqli_mock = Mock(spec=SQLiScanner)
        return [xss_mock, sqli_mock]

    @patch('app.services.scanner.ScannerFactory')
    def test_scanner_initialization(self, mock_factory, mock_scanners):
        # Configuration de la factory
        mock_factory.create_scanner.side_effect = mock_scanners
        
        scanner = Scanner()
        
        # Vérification de l'initialisation
        assert len(scanner.scanners) == 2
        mock_factory.create_scanner.assert_any_call("xss")
        mock_factory.create_scanner.assert_any_call("sqli")
        assert isinstance(scanner.scanners[0], Mock)
        assert isinstance(scanner.scanners[1], Mock)

    @patch('app.services.scanner.ScannerFactory')
    def test_scan_success(self, mock_factory, mock_scanners):
        # Configuration des mocks
        mock_factory.create_scanner.side_effect = mock_scanners
        mock_scanners[0].scan.return_value = [{"type": "XSS", "status": "Vulnerable"}]
        mock_scanners[1].scan.return_value = [{"type": "SQLi", "status": "Safe"}]

        scanner = Scanner()
        results = scanner.scan("http://test.com")

        # Vérifications
        assert len(results) == 2
        assert results[0][0]["type"] == "XSS"
        assert results[1][0]["type"] == "SQLi"
        mock_scanners[0].scan.assert_called_once_with("http://test.com")
        mock_scanners[1].scan.assert_called_once_with("http://test.com")

    @patch('app.services.scanner.ScannerFactory')
    def test_scan_with_exception(self, mock_factory, mock_scanners):
        # Simulation d'une exception
        mock_factory.create_scanner.side_effect = mock_scanners
        mock_scanners[0].scan.side_effect = Exception("Scan error")
        mock_scanners[1].scan.return_value = [{"type": "SQLi", "status": "Error"}]

        scanner = Scanner()
        
        with pytest.raises(Exception) as exc_info:
            scanner.scan("http://error.com")
        
        assert "Scan error" in str(exc_info.value)

    @patch('app.services.scanner.ScannerFactory')
    def test_scan_with_invalid_url(self, mock_factory, mock_scanners):
        # Test avec URL invalide
        mock_factory.create_scanner.side_effect = mock_scanners
        mock_scanners[0].scan.return_value = [{"status": "Error", "details": "Invalid URL"}]
        mock_scanners[1].scan.return_value = [{"status": "Error", "details": "Invalid URL"}]

        scanner = Scanner()
        results = scanner.scan("invalid_url")

        # Vérification des résultats d'erreur
        assert len(results) == 2
        assert results[0][0]["status"] == "Error"
        assert results[1][0]["status"] == "Error"

    @patch('app.services.scanner.ScannerFactory')
    def test_scan_empty_response(self, mock_factory, mock_scanners):
        # Test avec réponse vide
        mock_factory.create_scanner.side_effect = mock_scanners
        mock_scanners[0].scan.return_value = []
        mock_scanners[1].scan.return_value = []

        scanner = Scanner()
        results = scanner.scan("http://safe-site.com")

        # Vérification des résultats vides
        assert len(results) == 2
        assert results == [[], []]
        
import urllib.parse
from app.services.strategies.sqli import SQLiScanner  # Ajouter
from app.services.strategies.xss import XSSScanner    # Ajouter

def test_sqli_detects_error_based(requests_mock):
    scanner = SQLiScanner()
    test_url = "http://test.com"
    payload = scanner.payloads[0]
    encoded_payload = urllib.parse.quote(payload)
    
    # Mock adapté au payload réel
    requests_mock.get(
        f"{test_url}?q={encoded_payload}",
        text="unclosed quotation mark"
    )
    
    results = scanner.scan(test_url)
    assert any(res["status"] == "Vulnerable" for res in results)

def test_sqli_handles_timeout():
    scanner = SQLiScanner()
    results = scanner.scan("http://unreachable-site.com")
    assert results[0]["status"] == "Error"  # Vérification du statut

def test_scanners_handle_invalid_url():
    scanner = XSSScanner()
    results = scanner.scan("missing-scheme.com")
    assert "error" in results[0]["status"]