"""
AISOP Strongly Typed Security Entities.

Represents atomic entities extracted during security telemetry normalization.
These entities form the graph nodes for cross-evidence correlation, timeline assembly,
and threat intelligence lookups.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class ProcessEntity(BaseModel):
    """Process execution entity."""
    image_path: str | None = Field(default=None, description="Full filesystem path to process executable")
    process_name: str | None = Field(default=None, description="Executable name, e.g. cmd.exe")
    command_line: str | None = Field(default=None, description="Complete process command line including arguments")
    pid: int | None = Field(default=None, description="Process ID")
    ppid: int | None = Field(default=None, description="Parent Process ID")
    parent_image: str | None = Field(default=None, description="Filesystem path of parent process")
    parent_command_line: str | None = Field(default=None, description="Command line of parent process")
    process_guid: str | None = Field(default=None, description="Unique OS/Sysmon GUID for process")
    parent_process_guid: str | None = Field(default=None, description="Unique OS/Sysmon GUID for parent process")
    user: str | None = Field(default=None, description="User executing the process")
    integrity_level: str | None = Field(default=None, description="Process integrity level (e.g. High, System)")
    current_directory: str | None = Field(default=None, description="Working directory of process")
    hashes: dict[str, str] = Field(default_factory=dict, description="Process binary hashes (e.g. SHA256, MD5)")


class NetworkEntity(BaseModel):
    """Network connection / flow entity."""
    source_ip: str | None = Field(default=None, description="Source IPv4 or IPv6 address")
    source_port: int | None = Field(default=None, description="Source TCP/UDP port")
    destination_ip: str | None = Field(default=None, description="Destination IPv4 or IPv6 address")
    destination_port: int | None = Field(default=None, description="Destination TCP/UDP port")
    protocol: str | None = Field(default=None, description="Protocol name, e.g. tcp, udp, icmp")
    destination_hostname: str | None = Field(default=None, description="Destination domain or hostname if known")
    direction: str | None = Field(default=None, description="inbound, outbound, or unknown")
    initiated: bool | None = Field(default=None, description="True if connection initiated locally")


class UserEntity(BaseModel):
    """User account entity."""
    username: str | None = Field(default=None, description="Username or account name")
    domain: str | None = Field(default=None, description="Windows domain or host realm")
    sid: str | None = Field(default=None, description="Security Identifier (SID)")
    logon_id: str | None = Field(default=None, description="Logon session ID")
    logon_type: int | None = Field(default=None, description="Logon type (e.g. 2 for Interactive, 3 for Network)")


class HostEntity(BaseModel):
    """Host or machine endpoint entity."""
    hostname: str | None = Field(default=None, description="Computer or endpoint hostname")
    domain: str | None = Field(default=None, description="Domain the host is joined to")
    os: str | None = Field(default=None, description="Operating system name/version")
    ip_addresses: list[str] = Field(default_factory=list, description="Host-associated IP addresses")


class FileEntity(BaseModel):
    """Filesystem item entity."""
    path: str | None = Field(default=None, description="Full file path")
    filename: str | None = Field(default=None, description="File name without directory path")
    directory: str | None = Field(default=None, description="Directory path")
    size_bytes: int | None = Field(default=None, description="File size in bytes")
    hashes: dict[str, str] = Field(default_factory=dict, description="File hashes (MD5, SHA256, IMPHASH)")
    extension: str | None = Field(default=None, description="File extension")


class RegistryEntity(BaseModel):
    """Windows Registry entity."""
    key_path: str | None = Field(default=None, description="Full registry key path")
    value_name: str | None = Field(default=None, description="Registry value name")
    value_data: str | None = Field(default=None, description="Data assigned to registry key")
    operation: str | None = Field(default=None, description="SetValue, CreateKey, DeleteKey, DeleteValue")


class DnsEntity(BaseModel):
    """DNS resolution entity."""
    query_name: str | None = Field(default=None, description="Domain queried")
    query_type: str | None = Field(default=None, description="A, AAAA, TXT, MX, etc.")
    query_status: str | None = Field(default=None, description="Query status / RCODE")
    resolved_ips: list[str] = Field(default_factory=list, description="List of resolved IP addresses")
