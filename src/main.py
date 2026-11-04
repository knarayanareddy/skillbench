"""FastAPI Application Entrypoint for SkillBench."""
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from src.core.config import settings
from src.api.foundation import router as foundation_router
from src.api.skb import router as domain_router

app = FastAPI(
    title="SkillBench",
    description="Preregistered empirical evaluation and statistical benchmark engine for AI agent skills using isolated paired trials and bootstrap confidence bounds.",
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handler for Problem Details (RFC 7807)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "type": "urn:problem:internal-error",
            "title": "Internal Server Error",
            "status": 500,
            "detail": str(exc),
            "instance": str(request.url)
        }
    )

# Include Routers
app.include_router(foundation_router, prefix="/api/v1", tags=["Foundation"])
app.include_router(domain_router, prefix="/api/v1", tags=["SKB Domain"])

@app.get("/healthz", tags=["Health"])
async def healthz():
    """Service liveness probe."""
    return {
        "status": "pass",
        "service": "skillbench",
        "version": "0.2.0"
    }

@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "Welcome to SkillBench API",
        "docs": "/docs",
        "health": "/healthz"
    }
