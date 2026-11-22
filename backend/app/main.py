"""
AISOP Application Entrypoint.

AI Security Investigation & Operations Platform (AISOP) Backend API.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from app.api.router import root_api_router
from app.core.auth_throttle import AuthFailureThrottle
from app.core.config import get_settings, validate_production_settings
from app.core.errors import install_error_handlers
from pathlib import Path
from app.core.logging import setup_logging
from app.modules.ai.knowledge.retriever import KnowledgeRetriever
from app.modules.threatintel.feeds.manager import LocalFeedManager
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.middleware import RequestCorrelationMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware
from app.middleware.body_limit import SMALL_BODY_LIMITS, BodySizeLimitMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown hooks."""
    settings = get_settings()
    validate_production_settings(settings)  # refuses to start in production with default DB credentials or wildcard CORS
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

    # Initialize application-scoped Local Threat Intelligence Engine
    feed_manager = LocalFeedManager()
    feed_dir = Path(settings.LOCAL_TI_FEED_DIR)
    if not feed_dir.is_absolute():
        feed_dir = Path.cwd() / feed_dir
    feed_manager.load_feeds_from_directory(
        feed_dir=feed_dir,
        max_age_seconds=settings.LOCAL_TI_MAX_FEED_AGE_HOURS * 3600.0,
    )
    app.state.threat_intel_engine = LocalThreatIntelEngine(feed_manager=feed_manager)

    # Initialize application-scoped Semantic Knowledge Retriever
    try:
        app.state.knowledge_retriever = KnowledgeRetriever()
        logger.info("Knowledge retriever initialized in app.state")
    except Exception as exc:
        app.state.knowledge_retriever = None
        logger.warning(
            "Knowledge retriever initialization deferred or failed",
            error_type=type(exc).__name__,
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
        # Interactive docs and the schema describe every endpoint and are served only in development.
        docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
        redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
        openapi_url=f"{settings.API_V1_PREFIX}/openapi.json" if settings.ENVIRONMENT == "development" else None,
        lifespan=lifespan,
    )

    # Request body size limits for size-sensitive paths (Stage 6 closure: domain evidence import)
    app.add_middleware(BodySizeLimitMiddleware)
    # Second, separate cap for small-JSON write endpoints that have no byte limit of their own (OWASP API4:2023 review)
    app.add_middleware(BodySizeLimitMiddleware, limits=SMALL_BODY_LIMITS)

    # Ingress Rate Limiting & Abuse Prevention Middleware (P3-H4). Added before the security headers so the headers also wrap its 429s.
    app.add_middleware(
        RateLimitMiddleware,
        enabled=settings.RATE_LIMIT_ENABLED,
        requests_per_minute=settings.RATE_LIMIT_REQUESTS_PER_MINUTE,
        burst_capacity=settings.RATE_LIMIT_BURST_CAPACITY,
        trusted_proxies=settings.RATE_LIMIT_TRUSTED_PROXIES,
        expensive_requests_per_minute=settings.RATE_LIMIT_EXPENSIVE_PER_MINUTE,
        expensive_burst_capacity=max(1, settings.RATE_LIMIT_EXPENSIVE_PER_MINUTE // 2),
    )

    # Security Headers Middleware
    app.add_middleware(
        SecurityHeadersMiddleware,
        enabled=settings.SECURITY_HEADERS_ENABLED,
        trusted_proxies=settings.RATE_LIMIT_TRUSTED_PROXIES,
    )

    # Request correlation and observability middleware
    app.add_middleware(RequestCorrelationMiddleware)

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],  # the API implements no PUT or DELETE route
        allow_headers=["Authorization", "X-API-Key", "Content-Type", "X-Request-ID"],
    )

    # Stable error envelope (Phase 2.2): code, safe message, server-generated request_id; legacy detail preserved
    install_error_handlers(app)

    # API-key brute-force protection state (per application instance, in memory)
    app.state.auth_throttle = (
        AuthFailureThrottle(
            max_failures_per_ip=settings.AUTH_FAILURE_MAX_PER_IP,
            lockout_seconds=settings.AUTH_LOCKOUT_SECONDS,
        )
        if settings.AUTH_BRUTE_FORCE_PROTECTION_ENABLED
        else None
    )

    # Mount API routes
    app.include_router(root_api_router)

    @app.get("/", tags=["Root"])
    async def root():
        body = {
            "platform": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "operational",
        }
        if settings.ENVIRONMENT == "development":  # the docs are only served in development
            body["docs"] = "/docs"
        return body

    return app


app = create_app()
