from app.services.observers.abstract_observer import ScanObserver
from app.models.scan import ScanResult
from app.utils.logger import logger  # Votre logger existant

class LogNotifier:
    def on_success(self, url, results):
        print(f"✅ Scan completed for {url}")
        print(f"📊 Results: {len(results)} vulnerabilities found")

    def on_failure(self, url, error):
        print(f"❌ Scan failed for {url}")
        print(f"🔴 Error: {str(error)}")