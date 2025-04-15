from app.services.strategies.xss import XSSScanner
from app.services.strategies.sqli import SQLiScanner
from app.services.scanner_factory import ScannerFactory
from app.services.observers.scan_subject import ScanSubject
from app.services.observers.implementations.email_notifier import EmailNotifier
from app.services.observers.implementations.LogNotifier import LogNotifier



class Scanner:
    def __init__(self):
                # Récupère tous les scanners disponibles via la Factory
        self.scanners = [
            ScannerFactory.create_scanner("xss"),
            ScannerFactory.create_scanner("sqli")
        ]
        self.subject = ScanSubject()
        self._init_observers()

    def _init_observers(self):
        
        self.subject.attach(EmailNotifier())
        self.subject.attach(LogNotifier())


    def scan(self, url: str):
        results = []
        for scanner in self.scanners:
            results.append(scanner.scan(url))
        return results
    def execute_scan(self, url: str):
        try:
            results = self.scan(url)  # Appel original
            self.subject.notify_success(results)
            return results
        except Exception as e:
            self.subject.notify_failure(url, e)
            raise
