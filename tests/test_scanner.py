import pytest
from unittest.mock import patch, Mock
from app.services.scanner import Scanner

# Test du scanner avec mock pour éviter les appels réseau
def test_scanner():
    with patch('app.services.strategies.xss.requests.get') as mock_get:
        # Configurer le mock pour simuler une réponse HTTP
        mock_response = Mock()
        mock_response.text = "<html>Test content</html>"
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        # Créer l'instance du scanner et exécuter
        scanner = Scanner()
        results = scanner.scan("http://example.com")
        
        # Vérifier que le scanner a bien fonctionné
        assert isinstance(results, list)
        # Vérifier que le mock a été appelé
        mock_get.assert_called()