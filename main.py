from fastapi import FastAPI
from app.api.routes import scan, results
from app.core.database import init_db
# Initialisation de l'application FastAPI
app = FastAPI(title="Web Vulnerability Scanner", version="1.0")

# Inclusion des routes API
app.include_router(scan.router, prefix="/scan", tags=["Scan"])
app.include_router(results.router, prefix="/results", tags=["Results"])
init_db()

# Point d'entrée
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
