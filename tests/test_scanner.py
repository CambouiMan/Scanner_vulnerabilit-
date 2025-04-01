from app.services.scanner import Scanner

def test_scanner():
    scanner = Scanner()
    results = scanner.scan("http://example.com")
    assert len(results) == 2
