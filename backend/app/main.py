from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes.intelligence import router as intelligence_router
from app.routers import (
    alerts,
    analysts,
    assets,
    dashboard,
    findings,
    investigations,
)

from app.api.routes.intelligence import router as intelligence_router


app = FastAPI(
    title="SAT-SA API",
    description=(
        "Security analytics and SOC effectiveness "
        "assessment platform."
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Routers
# ============================================================

app.include_router(
    dashboard.router
)

app.include_router(
    alerts.router
)

app.include_router(
    analysts.router
)

app.include_router(
    assets.router
)

app.include_router(
    findings.router
)

app.include_router(
    investigations.router
)

app.include_router(
    intelligence_router,
)


# ============================================================
# Health
# ============================================================

@app.get("/")
def root():

    return {
        "success": True,
        "name": "SAT-SA",
        "message": "SAT-SA API is running",
        "version": "1.0.0",
    }


@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "service": "SAT-SA",
    }