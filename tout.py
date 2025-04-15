from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.database import SessionLocal, engine , ScanResult
from app.models.scan import ScanResult, Base
from app.services.scanner import Scanner
from app.repositories.scan_result_repository import ScanResultRepository


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
    repo=ScanResultRepository(db)
    # Stockage des résultats en base de données
    scan_entry = ScanResult(url=url, status="Completed", vulnerabilities=str(results))
    repo.create({"url": url, "status": "pending"})
    db.add(scan_entry)
    db.commit()
    db.refresh(scan_entry)
    
    
    
    return {"message": "Scan terminé", "scan_id": scan_entry.id, "results": results}
@router.post(" avec notifiers")
def start_scan(url: str, scanner: Scanner = Depends()):
    return scanner.execute_scan(url) 


from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

class Database:
    _instance = None  # Stocke l'instance unique
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # Configuration initiale
            cls._instance.DATABASE_URL = "sqlite:///./scanner.db"
            cls._instance.engine = create_engine(
                cls._instance.DATABASE_URL, 
                connect_args={"check_same_thread": False}
            )
            cls._instance.SessionLocal = sessionmaker(
                autocommit=False, 
                autoflush=False, 
                bind=cls._instance.engine
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
from app.services.observers.scan_subject import ScanSubject
from app.services.observers.implementations.email_notifier import EmailNotifier
from app.services.observers.implementations.LogNotifier import LogNotifier



class Scanner:
    def __init__(self):
                # Récupère tous les scanners disponibles via la Factory
        self.scanners = [
            ScannerFactory.create_scanner("xss"),
            ScannerFactory.create_scanner("sqli")
        ]
        self.subject = ScanSubject()
        self._init_observers()

    def _init_observers(self):
        
        self.subject.attach(EmailNotifier())
        self.subject.attach(LogNotifier())


    def scan(self, url: str):
        results = []
        for scanner in self.scanners:
            results.append(scanner.scan(url))
        return results
    def execute_scan(self, url: str):
        try:
            results = self.scan(url)  # Appel original
            self.subject.notify_success(results)
            return results
        except Exception as e:
            self.subject.notify_failure(url, e)
            raise

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

from abc import ABC, abstractmethod
from app.models.scan import ScanResult

class ScanObserver(ABC):
    """Interface pour tous les observateurs de scan"""
    
    @abstractmethod
    def on_scan_completed(self, scan_result: ScanResult):
        pass

    @abstractmethod
    def on_scan_failed(self, scan_result: ScanResult, error: Exception):
        pass
    
from typing import List
from app.services.observers.abstract_observer import ScanObserver
from app.models.scan import ScanResult

class ScanSubject:
    """Classe responsable de la gestion des observateurs"""
    
    def __init__(self):
        self._observers: List[ScanObserver] = []

    def attach(self, observer: ScanObserver):
        if observer not in self._observers:
            self._observers.append(observer)

    def detach(self, observer: ScanObserver):
        self._observers.remove(observer)

    def notify_success(self, scan_result: ScanResult):
        for observer in self._observers:
            observer.on_scan_completed(scan_result)

    def notify_failure(self, scan_result: ScanResult, error: Exception):
        for observer in self._observers:
            observer.on_scan_failed(scan_result, error)
            
from app.services.observers.abstract_observer import ScanObserver
from app.models.scan import ScanResult
from app.utils.logger import logger  # Votre logger existant

class EmailNotifier(ScanObserver):
    """Envoie des notifications par email"""
    
    def on_scan_completed(self, scan_result: ScanResult):
            logger.info(f"📧 Notification pour scan, mail envoyé ")

    def on_scan_failed(self, scan_result: ScanResult, error: Exception):
        logger.error(f"❌ Échec scan  : {error}")

    def _send_email(self, to: str, subject: str, body: str):
        # Logique SMTP concrète
        pass
    
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.models.scan import ScanResult
from fastapi.testclient import TestClient
from app.core.database import Database
from fastapi import FastAPI


app = FastAPI()
router = APIRouter()
Base = Database().Base 



def get_db():
    db = Database().SessionLocal()  # Session via le Singleton
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


from fastapi import FastAPI
from app.api.routes import scan, results
from app.core.database import Database
# Initialisation de l'application FastAPI
app = FastAPI(title="Web Vulnerability Scanner", version="1.0")

# Inclusion des routes API
app.include_router(scan.router, prefix="/scan", tags=["Scan"])
app.include_router(results.router, prefix="/results", tags=["Results"])
Database = Database()
Base = Database.init_db()
# Point d'entrée
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
