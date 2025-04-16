import pytest
from app.services.strategies.sqli import SQLiScanner
from app.services.strategies.sqli import SQLiScanner

@pytest.fixture
def scanner():
    scanner = SQLiScanner()
    scanner.payloads = ["' OR '1'='1"]  # Mock des payloads pour éviter la lecture de fichier
    return scanner

def test_sqli_vulnerable(scanner, monkeypatch):
    class MockResponse:
        text = "You have an error in your SQL syntax"

    def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("app.services.strategies.sqli.requests.get", mock_get)

    url = "http://example.com/search"
    result = scanner.scan(url)

    assert len(result) == 1
    assert result[0]["status"] == "Vulnerable"
    assert result[0]["payload"] == "' OR '1'='1"

def test_sqli_safe(scanner, monkeypatch):
    class MockResponse:
        text = "Page loaded successfully with no error"

    def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("app.services.strategies.sqli.requests.get", mock_get)

    url = "http://example.com/search"
    result = scanner.scan(url)

    assert len(result) == 1
    assert result[0]["status"] == "Safe"
