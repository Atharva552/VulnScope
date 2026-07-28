from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routers.home import router as home_router
from app.routers.scan import router as scan_router
from app.routers.dashboard import router as dashboard_router


app = FastAPI(
    title="VulnScope",
    description="Basic Vulnerability Assessment & Penetration Testing Scanner",
    version="1.0.0"
)


# Static Files
app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static"
)


# Routers
app.include_router(home_router)
app.include_router(scan_router)
app.include_router(dashboard_router)


@app.get("/health")
def health_check():
    return {
        "status": "running",
        "application": "VulnScope",
        "version": "1.0.0"
    }