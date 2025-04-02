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