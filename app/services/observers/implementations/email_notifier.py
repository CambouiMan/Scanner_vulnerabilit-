from app.services.observers.abstract_observer import ScanObserver
from app.models.scan import ScanResult
from app.utils.logger import logger  # Votre logger existant

class EmailNotifier(ScanObserver):
    """Envoie des notifications par email"""
    
    def on_scan_completed(self, scan_result: ScanResult):
            logger.info(f"📧 Notification pour scan, mail envoyé ")

    def on_scan_failed(self, scan_result: ScanResult, error: Exception):
        logger.error(f"❌ Échec scan  : {error}")

    def _send_email(self, to: str, subject: str, body: str):
        # Logique SMTP concrète
        pass