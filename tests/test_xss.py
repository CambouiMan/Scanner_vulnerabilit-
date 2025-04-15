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