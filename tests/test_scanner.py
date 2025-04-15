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