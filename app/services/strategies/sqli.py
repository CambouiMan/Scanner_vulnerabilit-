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
        vulnerabilities = []
        sql_errors = [
            "you have an error in your sql syntax", 
            "warning: mysql", 
            "unclosed quotation mark after the character string",
            "sql error"
        ]

        for payload in self.payloads:
            try:
                encoded_payload = urllib.parse.quote(payload)
                full_url = f"{url}?q={encoded_payload}"
                response = requests.get(full_url, timeout=5)

                if any(error in response.text.lower() for error in sql_errors):
                    vulnerabilities.append({
                        "type": "SQLi",
                        "url": url,
                        "payload": payload,
                        "status": "Vulnerable"
                    })

            except requests.RequestException as e:
                return [{
                    "type": "SQLi",
                    "url": url,
                    "status": "Error",
                    "details": str(e)
                }]  # Retour immédiat en cas d'erreur

        # Retourne "Safe" SEULEMENT si aucune vulnérabilité ni erreur
        return vulnerabilities if vulnerabilities else [{
            "type": "SQLi",
            "url": url,
            "status": "Safe"
        }]