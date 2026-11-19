"""
AISOP Concrete Alert Adapters.

Exports all 8 canonical vendor alert adapters.
"""

from app.modules.alerts.adapters.cloud_audit_adapter import CloudAuditAdapter
from app.modules.alerts.adapters.edr_malware_adapter import EdrMalwareAdapter
from app.modules.alerts.adapters.email_phishing_adapter import EmailPhishingAdapter
from app.modules.alerts.adapters.firewall_ids_adapter import NetworkIdsAdapter
from app.modules.alerts.adapters.generic_siem_adapter import GenericSiemAdapter
from app.modules.alerts.adapters.linux_auth_adapter import LinuxAuthAdapter
from app.modules.alerts.adapters.sysmon_adapter import SysmonAlertAdapter
from app.modules.alerts.adapters.windows_security_adapter import WindowsSecurityAdapter

__all__ = [
    "CloudAuditAdapter",
    "EdrMalwareAdapter",
    "EmailPhishingAdapter",
    "GenericSiemAdapter",
    "LinuxAuthAdapter",
    "NetworkIdsAdapter",
    "SysmonAlertAdapter",
    "WindowsSecurityAdapter",
]

