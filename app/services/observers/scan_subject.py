from typing import List
from app.services.observers.abstract_observer import ScanObserver
from app.models.scan import ScanResult

class ScanSubject:
    """Classe responsable de la gestion des observateurs"""
    
    def __init__(self):
        self._observers: List[ScanObserver] = []

    def attach(self, observer: ScanObserver):
        if observer not in self._observers:
            self._observers.append(observer)

    def detach(self, observer: ScanObserver):
        self._observers.remove(observer)

    def notify_success(self, scan_result: ScanResult):
        for observer in self._observers:
            observer.on_scan_completed(scan_result)

    def notify_failure(self, scan_result: ScanResult, error: Exception):
        for observer in self._observers:
            observer.on_scan_failed(scan_result, error)