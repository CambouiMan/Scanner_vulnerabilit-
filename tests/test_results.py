from app.models.scan import ScanResult
from app.repositories.scan_result_repository import ScanResultRepository
from app.core.database import Database
import pytest

class TestScanResult:
    @pytest.fixture
    def db(self):
        return Database().SessionLocal()

    @pytest.fixture
    def repo(self, db):
        return ScanResultRepository(db)

    def test_scan_result_creation(self, repo):
        scan_data = {
            "url": "http://test.com",
            "status": "pending"
        }
        result = repo.create(scan_data)
        assert result.id is not None
        assert result.url == scan_data["url"]

    def test_get_scan_result(self, repo):
        scan = repo.create({"url": "http://get-test.com", "status": "completed"})
        fetched = repo.get_by_id(scan.id)
        assert fetched.id == scan.id
        assert fetched.status == "completed"