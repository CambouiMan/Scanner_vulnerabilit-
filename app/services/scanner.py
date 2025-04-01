from app.services.strategies.xss import XSSScanner
from app.services.strategies.sqli import SQLiScanner
from app.services.scanner_factory import ScannerFactory

class Scanner:
    def __init__(self):
                # Récupère tous les scanners disponibles via la Factory
        self.scanners = [
            ScannerFactory.create_scanner("xss"),
            ScannerFactory.create_scanner("sqli")
        ]

    def scan(self, url: str):
        results = []
        for scanner in self.scanners:
            results.append(scanner.scan(url))
        return results
