"""
AISOP API v1 Router.
"""

from fastapi import APIRouter, Depends
from app.api.dependencies import verify_api_key
from app.api.v1.endpoints.alerts import router as alerts_router
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.cases import router as cases_router
from app.api.v1.endpoints.evidence import router as evidence_router
from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.investigations import router as investigations_router
from app.api.v1.endpoints.reports import router as reports_router
from app.api.v1.endpoints.security import router as security_router

# Protected API v1 router: all child routes require verified API authentication
protected_v1_router = APIRouter(dependencies=[Depends(verify_api_key)])
protected_v1_router.include_router(alerts_router)
protected_v1_router.include_router(auth_router)
protected_v1_router.include_router(cases_router)
protected_v1_router.include_router(evidence_router)
protected_v1_router.include_router(investigations_router)
protected_v1_router.include_router(reports_router)
protected_v1_router.include_router(security_router)

# Combined API v1 router
api_v1_router = APIRouter()
# Health probes remain explicitly public for orchestrators and container health
api_v1_router.include_router(health_router)
# Include all authenticated routes under the protected perimeter
api_v1_router.include_router(protected_v1_router)
