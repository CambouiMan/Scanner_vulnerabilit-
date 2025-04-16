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

from app.models.scan import ScanResult
from app.repositories.scan_result_repository import ScanResultRepository
from app.core.database import Database
import pytest

class TestScanResult:
    @pytest.fixture
    def db(self):
        return Database().SessionLocal()

    @pytest.fixture
    def repo(self, db):
        return ScanResultRepository(db)

    def test_scan_result_creation(self, repo):
        scan_data = {
            "url": "http://test.com",
            "status": "pending"
        }
        result = repo.create(scan_data)
        assert result.id is not None
        assert result.url == scan_data["url"]

    def test_get_scan_result(self, repo):
        scan = repo.create({"url": "http://get-test.com", "status": "completed"})
        fetched = repo.get_by_id(scan.id)
        assert fetched.id == scan.id
        assert fetched.status == "completed"
        
import pytest
from unittest.mock import Mock, patch
from app.services.scanner import Scanner
from app.services.observers.implementations.email_notifier import EmailNotifier

class TestScanner:
    @patch('app.services.scanner.ScannerFactory.create_scanner')
    def test_scanner_initialization(self, mock_factory):
        mock_factory.side_effect = [Mock(), Mock()]
        scanner = Scanner()
        assert len(scanner.scanners) == 2
        assert len(scanner.subject._observers) == 2


    @patch('app.services.scanner.Scanner.scan')
    def test_execute_scan_failure(self, mock_scan):
        scanner = Scanner()
        mock_scan.side_effect = Exception("Scan failed")
        
        with pytest.raises(Exception):
            scanner.execute_scan("http://fail.com")
            
import pytest
import requests
import requests_mock
from app.services.strategies.sqli import SQLiScanner

class TestSQLiScanner:
    @pytest.fixture
    def scanner(self):
        return SQLiScanner()

    def test_detect_sqli_vulnerability(self, scanner):
        test_url = "http://vuln-site.com"
        payload = scanner.payloads[0]
        
        with requests_mock.Mocker() as m:
            m.get(
                f"{test_url}?q={payload}", 
                text="you have an error in your sql syntax"
            )
            results = scanner.scan(test_url)
            
        assert any(res["status"] == "Vulnerable" for res in results)

    def test_handle_request_timeout(self, scanner):
        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, exc=requests.exceptions.ConnectTimeout)
            results = scanner.scan("http://unreachable.com")
            
        assert results[0]["status"] == "Error"

import pytest
import requests_mock
from app.services.strategies.xss import XSSScanner

class TestXSSScanner:
    @pytest.fixture
    def scanner(self):
        return XSSScanner()

    def test_detect_xss_vulnerability(self, scanner):
        test_url = "http://xss-site.com"
        payload = scanner.payloads[0]
        
        with requests_mock.Mocker() as m:
            m.get(f"{test_url}?q={payload}", text=payload)
            results = scanner.scan(test_url)
            
        assert any(res["status"] == "Vulnerable" for res in results)

    def test_no_xss_detected(self, scanner):
        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, text="safe content")
            results = scanner.scan("http://safe-site.com")
            
        assert all(res["status"] == "Safe" for res in results)