"""
AISOP Alert Processing & Normalization Module.
"""

from app.modules.alerts.adapter_protocol import (
    AlertAdapterRegistry,
    BaseAlertAdapter,
    get_default_registry,
)

__all__ = [
    "AlertAdapterRegistry",
    "BaseAlertAdapter",
    "get_default_registry",
]

