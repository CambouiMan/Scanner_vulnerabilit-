# Web Vulnerability Scanner

Ce projet est un scanner de vulnérabilités web développé avec **FastAPI**. Il permet de détecter des vulnérabilités courantes telles que les injections SQL (SQLi) et les attaques par script intersite (XSS) sur des sites web.

## Fonctionnalités

- **Détection des vulnérabilités SQLi** : Identifie les erreurs SQL en injectant des charges utiles malveillantes.
- **Détection des vulnérabilités XSS** : Vérifie si des scripts malveillants peuvent être exécutés sur une page web.
- **Stockage des résultats** : Les résultats des scans sont enregistrés dans une base de données SQLite.
- **Notifications** : Notifications via des observateurs (log et email) en cas de succès ou d'échec d'un scan.
- **API REST** : Fournit des endpoints pour lancer des scans et récupérer les résultats.
- **Extensibilité** : Architecture modulaire permettant d'ajouter facilement de nouveaux types de scanners.

---

## Installation

### Prérequis

- Python 3.10 ou supérieur
- Pip (gestionnaire de paquets Python)

### Étapes

1. Clonez le dépôt :
   ```sh
   git clone <repository-url>
   cd Scanner_vulnerabilit-
   ```

2. Installez les dépendances :
   ```sh
   pip install -r requirements.txt
   ```

3. Initialisez la base de données :
   ```sh
   python -c "from app.core.database import Database; Database().init_db()"
   ```

---

## Utilisation

### Lancer l'API

Pour démarrer le serveur FastAPI en mode développement :
```sh
uvicorn main:app --reload
```

L'API sera accessible à l'adresse suivante : [http://127.0.0.1:8000](http://127.0.0.1:8000)

### Endpoints disponibles

#### 1. **Lancer un scan**
- **Méthode** : `POST`
- **URL** : `/scan/`
- **Paramètres** :
  - `url` (str) : L'URL cible à scanner.
- **Exemple** :
  ```sh
  curl -X POST "http://127.0.0.1:8000/scan/" -d "url=http://example.com"
  ```
- **Réponse** :
  ```json
  {
    "message": "Scan terminé",
    "scan_id": 1,
    "results": [
      {
        "type": "XSS",
        "url": "http://example.com",
        "status": "Safe"
      },
      {
        "type": "SQLi",
        "url": "http://example.com",
        "status": "Safe"
      }
    ]
  }
  ```

#### 2. **Récupérer les résultats d'un scan**
- **Méthode** : `GET`
- **URL** : `/results/{scan_id}`
- **Exemple** :
  ```sh
  curl -X GET "http://127.0.0.1:8000/results/1"
  ```
- **Réponse** :
  ```json
  {
    "scan_id": 1,
    "url": "http://example.com",
    "status": "Completed",
    "vulnerabilities": [
      {
        "type": "XSS",
        "status": "Safe"
      },
      {
        "type": "SQLi",
        "status": "Safe"
      }
    ],
    "timestamp": "2023-10-01T12:00:00Z"
  }
  ```

#### 3. **Lister tous les scans**
- **Méthode** : `GET`
- **URL** : `/results/`
- **Exemple** :
  ```sh
  curl -X GET "http://127.0.0.1:8000/results/"
  ```
- **Réponse** :
  ```json
  [
    {
      "scan_id": 1,
      "url": "http://example.com",
      "status": "Completed"
    }
  ]
  ```

---

## Structure du Projet

```
Scanner_vulnerabilit-
├── app/
│   ├── api/
│   │   └── routes/
│   │       ├── scan.py         # Endpoints pour lancer des scans
│   │       ├── results.py      # Endpoints pour récupérer les résultats
│   ├── core/
│   │   ├── database.py         # Configuration de la base de données
│   │   └── config.py           # Configuration globale
│   ├── models/
│   │   └── scan.py             # Modèle de données pour les résultats de scan
│   ├── repositories/
│   │   └── scan_result_repository.py  # Gestion des résultats dans la base
│   ├── services/
│   │   ├── scanner.py          # Gestion des scanners
│   │   ├── scanner_factory.py  # Factory pour créer des scanners
│   │   ├── strategies/         # Implémentations des scanners (SQLi, XSS)
│   │   └── observers/          # Observateurs pour les notifications
│   ├── utils/
│   │   ├── logger.py           # Gestion des logs
│   │   └── report.py           # Génération de rapports
├── payloads/
│   ├── sqli_payloads.txt       # Payloads pour les tests SQLi
│   └── xss_payloads.txt        # Payloads pour les tests XSS
├── tests/
│   ├── test_scanner.py         # Tests unitaires pour le scanner
│   ├── test_sqli.py            # Tests pour le scanner SQLi
│   ├── test_xss.py             # Tests pour le scanner XSS
│   └── ...                     # Autres tests
├── main.py                     # Point d'entrée de l'application
├── requirements.txt            # Dépendances Python
└── README.md                   # Documentation
```

---

## Tests

Pour exécuter les tests unitaires :
```sh
pytest
```

Les tests couvrent :
- Les fonctionnalités des scanners (SQLi, XSS).
- Les interactions avec la base de données.
- Les endpoints de l'API.

---

## Extensibilité

### Ajouter un nouveau type de scanner

1. Créez une nouvelle classe dans `app/services/strategies/` qui hérite de `BaseScanner`.
2. Implémentez la méthode `scan`.
3. Ajoutez le scanner dans la `ScannerFactory` :
   ```py
   scanners = {
       "xss": XSSScanner,
       "sqli": SQLiScanner,
       "nouveau_scanner": NouveauScanner
   }
   ```

---


---
