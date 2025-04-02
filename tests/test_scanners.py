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