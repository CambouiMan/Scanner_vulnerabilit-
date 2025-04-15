from app.services.strategies.xss import XSSScanner
from app.services.strategies.sqli import SQLiScanner
from app.services.strategies.base import BaseScanner


class ScannerFactory:
    @staticmethod
    def create_scanner(scanner_type: str) -> BaseScanner:
        """Factory pour créer des scanners dynamiquement."""
        scanners = {
            "xss": XSSScanner,
            "sqli": SQLiScanner
        }
        if scanner_type not in scanners:
            raise ValueError(f"Scanner non supporté : {scanner_type}")
        return scanners[scanner_type]()