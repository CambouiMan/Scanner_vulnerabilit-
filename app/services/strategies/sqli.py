import requests
import os
import urllib.parse
from app.services.strategies.base import BaseScanner

class SQLiScanner(BaseScanner):
    def __init__(self, payload_file="app/payloads/sqli_payloads.txt"):
        self.payloads = self.load_payloads(payload_file)

    def load_payloads(self, file_path):
        """Charge les payloads SQLi depuis un fichier externe"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"⚠️ Fichier {file_path} introuvable. Utilisation d'un payload par défaut.")
            return ["' OR '1'='1"]  # Payload par défaut

    def scan(self, url: str):
        """Teste les injections SQL sur l'URL fournie"""
        vulnerabilities = []
        sql_errors = [
            "you have an error in your sql syntax", 
            "warning: mysql", 
            "unclosed quotation mark after the character string",
            "sql error"
        ]

        for payload in self.payloads:
            encoded_payload = urllib.parse.quote(payload)  # Encodage pour éviter les erreurs
            full_url = f"{url}?q={encoded_payload}"

            try:
                response = requests.get(full_url, timeout=5)

                # Vérifie si la page renvoie une erreur SQL spécifique
                if any(error in response.text.lower() for error in sql_errors):
                    vulnerabilities.append({
                        "type": "SQLi",
                        "url": url,
                        "payload": payload,
                        "status": "Vulnerable"
                    })

            except requests.RequestException:
                print(f"⚠️ Erreur lors de la requête vers {full_url}")

        return vulnerabilities if vulnerabilities else [{"type": "SQLi", "url": url, "status": "Safe"}]
