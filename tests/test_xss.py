import pytest
import requests_mock
from app.services.strategies.xss import XSSScanner

def test_xss_scanner_vulnerable():
    scanner = XSSScanner()
    test_url = "http://example.com"
    payload = "<script>alert('XSS')</script>"
    
    with requests_mock.Mocker() as mocker:
        mocker.get(f"{test_url}?q={payload}", text=payload)
        results = scanner.scan(test_url)
        
    assert results[0]["status"] == "Vulnerable"
    assert results[0]["payload"] == payload

def test_xss_scanner_safe():
    scanner = XSSScanner()
    test_url = "http://example.com"
    
    with requests_mock.Mocker() as mocker:
        mocker.get(f"{test_url}?q=<script>alert('XSS')</script>", text="Safe Response")
        results = scanner.scan(test_url)
        
    assert results[0]["status"] == "Safe"

def test_xss_scanner_file_not_found():
    scanner = XSSScanner(payload_file="non_existent.txt")
    assert scanner.payloads == ["<script>alert('XSS')</script>"]