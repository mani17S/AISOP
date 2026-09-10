"""
AISOP Central API Router.
"""

from fastapi import APIRouter
from app.api.v1 import api_v1_router
from app.core.config import get_settings

settings = get_settings()

root_api_router = APIRouter()
root_api_router.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)
