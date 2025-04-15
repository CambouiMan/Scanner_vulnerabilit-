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