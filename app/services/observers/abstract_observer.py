from abc import ABC, abstractmethod
from app.models.scan import ScanResult

class ScanObserver(ABC):
    """Interface pour tous les observateurs de scan"""
    
    @abstractmethod
    def on_scan_completed(self, scan_result: ScanResult):
        pass

    @abstractmethod
    def on_scan_failed(self, scan_result: ScanResult, error: Exception):
        pass