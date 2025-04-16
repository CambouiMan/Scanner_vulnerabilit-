import pytest
from app.services.strategies.xss import XSSScanner

@pytest.fixture
def scanner():
    scanner = XSSScanner()
    scanner.payloads = ["<script>alert('XSS')</script>"]
    return scanner

def test_xss_vulnerable(scanner, monkeypatch):
    class MockResponse:
        text = "Welcome <script>alert('XSS')</script>!"

    def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("app.services.strategies.xss.requests.get", mock_get)

    url = "http://example.com/search"
    result = scanner.scan(url)

    assert len(result) == 1
    assert result[0]["status"] == "Vulnerable"
    assert result[0]["payload"] == "<script>alert('XSS')</script>"

def test_xss_safe(scanner, monkeypatch):
    class MockResponse:
        text = "Welcome user, nothing to see here"

    def mock_get(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr("app.services.strategies.xss.requests.get", mock_get)

    url = "http://example.com/search"
    result = scanner.scan(url)

    assert len(result) == 1
    assert result[0]["status"] == "Safe"

def test_xss_default_payload(monkeypatch, tmp_path):
    # Crée un chemin invalide pour forcer l'utilisation du payload par défaut
    fake_path = tmp_path / "inexistant_payloads.txt"
    scanner = XSSScanner(payload_file=str(fake_path))

    assert scanner.payloads == ["<script>alert('XSS')</script>"]
