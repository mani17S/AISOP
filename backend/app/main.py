"""
AISOP Application Entrypoint.

AI Security Investigation & Operations Platform (AISOP) Backend API.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from app.api.router import root_api_router
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.middleware.correlation import RequestCorrelationMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown hooks."""
    settings = get_settings()
    setup_logging(settings)
    logger.info(
        "Starting AISOP application",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
        log_level=settings.LOG_LEVEL,
        log_format=settings.LOG_FORMAT,
    )
    yield
    logger.info("Shutting down AISOP application")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="AISOP — AI Security Investigation & Operations Platform Backend",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
        lifespan=lifespan,
    )

    # Request correlation and observability middleware
    app.add_middleware(RequestCorrelationMiddleware)

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routes
    app.include_router(root_api_router)

    @app.get("/", tags=["Root"])
    async def root():
        return {
            "platform": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "operational",
            "docs": "/docs",
        }

    return app


app = create_app()
