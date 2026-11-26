"""
AISOP Application Entrypoint.

AI Security Investigation & Operations Platform (AISOP) Backend API.
"""

from __future__ import annotations

import asyncio
import gc
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from app.api.router import root_api_router
from app.core.auth_throttle import AuthFailureThrottle
from app.core.config import get_settings, validate_production_settings
from app.core.errors import install_error_handlers
from pathlib import Path
from app.core.logging import setup_logging
from app.core.security_events import SecurityEventBuffer
from app.modules.ai.knowledge.retriever import KnowledgeRetriever
from app.modules.threatintel.feeds.manager import LocalFeedManager
from app.modules.threatintel.local_engine import LocalThreatIntelEngine
from app.services import analysis_executor
from app.middleware import RequestCorrelationMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware
from app.middleware.body_limit import SMALL_BODY_LIMITS, BodySizeLimitMiddleware
from app.middleware.security_events import SecurityEventsMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger


SECURITY_EVENTS_FLUSH_SECONDS = 10
SECURITY_EVENTS_RETENTION_DAYS = 30
SECURITY_ALERT_NOTIFY_SECONDS = 60


async def _flush_security_events_once(app: FastAPI) -> None:
    """Write the in-memory security event counts to the database. A failure is logged, never raised into the server."""
    from app.db.session import get_session_factory
    from app.services.security_event_service import flush_security_events

    buffer = getattr(app.state, "security_events", None)
    if buffer is None:
        return
    try:
        async with get_session_factory()() as session:
            await flush_security_events(buffer, session)
    except Exception as exc:
        logger.warning("Security event flush failed", error_type=type(exc).__name__)


async def _notify_security_alerts_once(app: FastAPI) -> None:
    """Derive the current platform alerts and hand them to the notifier (log always; webhook only if configured). Never raises into the server."""
    from app.db.session import get_session_factory
    from app.services.security_event_service import current_alerts

    dispatcher = getattr(app.state, "security_alerts", None)
    if dispatcher is None:
        return
    try:
        async with get_session_factory()() as session:
            alerts = await current_alerts(session)
        await dispatcher.handle(alerts)
    except Exception as exc:
        logger.warning("Security alert notification failed", error_type=type(exc).__name__)


async def _security_events_loop(app: FastAPI) -> None:
    from app.db.session import get_session_factory
    from app.services.security_event_service import purge_older_than

    ticks_per_purge = max(1, 3600 // SECURITY_EVENTS_FLUSH_SECONDS)
    ticks_per_notify = max(1, SECURITY_ALERT_NOTIFY_SECONDS // SECURITY_EVENTS_FLUSH_SECONDS)
    tick = 0
    while True:
        await asyncio.sleep(SECURITY_EVENTS_FLUSH_SECONDS)
        await _flush_security_events_once(app)
        tick += 1
        if tick % ticks_per_notify == 0:
            await _notify_security_alerts_once(app)
        if tick % ticks_per_purge == 0:
            try:
                async with get_session_factory()() as session:
                    await purge_older_than(session, SECURITY_EVENTS_RETENTION_DAYS)
            except Exception as exc:
                logger.warning("Security event purge failed", error_type=type(exc).__name__)


def _freeze_gc_after_startup() -> None:
    """Opt-in (GC_FREEZE_AT_STARTUP): collect once, then move the start-up objects to the permanent generation so later full collections are shorter."""
    try:
        gc.collect()
        gc.freeze()
        logger.info("Garbage collector frozen after start-up", frozen_objects=gc.get_freeze_count())
    except Exception as exc:
        logger.warning("Garbage collector freeze failed", error_type=type(exc).__name__)


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

    flush_task = asyncio.create_task(_security_events_loop(app))
    # Optional worker processes for the deterministic investigation (ANALYSIS_WORKER_PROCESSES, default 0 = off). Started in the background so
    # the 2 to 3 s warm-up never delays startup; start_pool logs and returns on failure, so the app starts either way.
    pool_task = asyncio.create_task(analysis_executor.start_pool())
    if settings.GC_FREEZE_AT_STARTUP:
        _freeze_gc_after_startup()
    yield
    pool_task.cancel()
    try:
        await pool_task
    except asyncio.CancelledError:
        pass
    await analysis_executor.shutdown_pool()
    flush_task.cancel()
    try:
        await flush_task
    except asyncio.CancelledError:
        pass
    await _flush_security_events_once(app)
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

    # Attack visibility: counts suspicious responses (Security page). Outside the limiter and size caps so their answers are seen.
    app.state.security_events = SecurityEventBuffer()
    from app.core.security_alerts import dispatcher_from_settings

    app.state.security_alerts = dispatcher_from_settings(get_settings())
    app.add_middleware(SecurityEventsMiddleware, trusted_proxies=settings.RATE_LIMIT_TRUSTED_PROXIES)

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
