from fastapi import FastAPI

app = FastAPI(
    title="SAT-SA",
    description="SOC Audit & Supervision Assistant",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SAT-SA",
        "version": "0.1.0",
    }