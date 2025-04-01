from abc import ABC, abstractmethod

class BaseScanner(ABC):
    @abstractmethod
    def scan(self, url: str):
        pass
