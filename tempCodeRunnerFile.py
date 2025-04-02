app = FastAPI(title="Web Vulnerability Scanner", version="1.0")

# Inclusion des routes API
app.include_router(scan.router, prefix="/scan", tags=["Scan"])
app.include_router(results.router, prefix="/results", tags=["Results"])