import requests
import os
import urllib.parse
from app.services.strategies.base import BaseScanner

class XSSScanner(BaseScanner):
    def __init__(self, payload_file="app/payloads/xss_payloads.txt"):
        self.payloads = self.load_payloads(payload_file)

    def load_payloads(self, file_path):
        """Charge les payloads XSS depuis un fichier externe"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"⚠️ Fichier {file_path} introuvable. Utilisation d'un payload par défaut.")
            return ["<script>alert('XSS')</script>"]  # Payload par défaut

    def scan(self, url: str):
        """Teste les injections XSS sur l'URL fournie"""
        vulnerabilities = []
        for payload in self.payloads:
            encoded_payload = urllib.parse.quote(payload)  # Encodage pour éviter les erreurs
            response = requests.get(f"{url}?q={encoded_payload}")

            if payload in response.text:  # Vérifie si la réponse contient le payload injecté
                vulnerabilities.append({
                    "type": "XSS",
                    "url": url,
                    "payload": payload,
                    "status": "Vulnerable"
                })

        return vulnerabilities if vulnerabilities else [{"type": "XSS", "url": url, "status": "Safe"}]
