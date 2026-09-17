"""
AISOP Atomic Entity Extractor.

Extracts queryable, indexed entities from CanonicalEvents for cross-evidence
correlation, entity graph generation, and threat intelligence lookups.
"""

from __future__ import annotations

from typing import Any

from app.schemas.normalized_event import CanonicalEvent
from pydantic import BaseModel, Field


class ExtractedEntityRecord(BaseModel):
    """
    Flat representation of an atomic entity extracted from a CanonicalEvent.
    """

    entity_type: str = Field(
        description="ip, host, user, process, file_hash, domain, file, registry"
    )
    entity_value: str = Field(
        description="The normalized identifier value for this entity"
    )
    role: str = Field(
        description="source, destination, parent, child, target, subject, actor"
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict, description="Contextual attributes"
    )


def extract_entities(event: CanonicalEvent) -> list[ExtractedEntityRecord]:
    """
    Extract all atomic entities from a CanonicalEvent.
    """
    entities: list[ExtractedEntityRecord] = []

    # 1. Host Entity
    if event.host and event.host.hostname:
        entities.append(
            ExtractedEntityRecord(
                entity_type="host",
                entity_value=event.host.hostname.upper(),
                role="endpoint",
                attributes={"domain": event.host.domain, "os": event.host.os},
            )
        )

    # 2. User Entity
    if event.user and event.user.username:
        full_user = (
            f"{event.user.domain}\\{event.user.username}"
            if event.user.domain
            else event.user.username
        )
        entities.append(
            ExtractedEntityRecord(
                entity_type="user",
                entity_value=full_user.lower(),
                role="actor",
                attributes={
                    "username": event.user.username,
                    "domain": event.user.domain,
                    "sid": event.user.sid,
                    "logon_id": event.user.logon_id,
                },
            )
        )

    # 3. Process Entities (Child / Executed / Source Process)
    if event.process:
        if event.process.process_name:
            if event.event_id in ("8", "10"):
                proc_role = "source"
            elif event.process.parent_image:
                proc_role = "child"
            else:
                proc_role = "executed"

            proc_attrs: dict[str, Any] = {
                "image_path": event.process.image_path,
                "command_line": event.process.command_line,
                "pid": event.process.pid,
                "ppid": event.process.ppid,
            }
            if event.process.process_guid:
                proc_attrs["process_guid"] = event.process.process_guid

            entities.append(
                ExtractedEntityRecord(
                    entity_type="process",
                    entity_value=event.process.process_name.lower(),
                    role=proc_role,
                    attributes=proc_attrs,
                )
            )

        # Parent Process
        if event.process.parent_image:
            parent_name = event.process.parent_image.split("\\")[-1].split("/")[-1]
            entities.append(
                ExtractedEntityRecord(
                    entity_type="process",
                    entity_value=parent_name.lower(),
                    role="parent",
                    attributes={
                        "image_path": event.process.parent_image,
                        "command_line": event.process.parent_command_line,
                        "pid": event.process.ppid,
                    },
                )
            )

        # Hashes from Process
        for algo, hash_val in event.process.hashes.items():
            if hash_val:
                entities.append(
                    ExtractedEntityRecord(
                        entity_type="file_hash",
                        entity_value=hash_val.lower(),
                        role="process_hash",
                        attributes={
                            "algorithm": algo.upper(),
                            "process": event.process.process_name,
                        },
                    )
                )

    # 3b. Target Process Entity (e.g. from Event 8 CreateRemoteThread or Event 10 ProcessAccess)
    target_proc_name = event.custom_fields.get("target_process_name")
    if target_proc_name and isinstance(target_proc_name, str):
        target_attrs: dict[str, Any] = {}
        if event.custom_fields.get("target_image"):
            target_attrs["image_path"] = str(event.custom_fields["target_image"])
        if event.custom_fields.get("target_process_id") is not None:
            target_attrs["pid"] = event.custom_fields["target_process_id"]
        if event.custom_fields.get("target_process_guid"):
            target_attrs["process_guid"] = str(
                event.custom_fields["target_process_guid"]
            )
        if event.custom_fields.get("granted_access"):
            target_attrs["granted_access"] = str(event.custom_fields["granted_access"])
        if event.custom_fields.get("call_trace"):
            target_attrs["call_trace"] = str(event.custom_fields["call_trace"])
        if event.custom_fields.get("new_thread_id") is not None:
            target_attrs["new_thread_id"] = event.custom_fields["new_thread_id"]
        if event.custom_fields.get("start_address"):
            target_attrs["start_address"] = str(event.custom_fields["start_address"])
        if event.custom_fields.get("start_module"):
            target_attrs["start_module"] = str(event.custom_fields["start_module"])
        if event.custom_fields.get("start_function"):
            target_attrs["start_function"] = str(event.custom_fields["start_function"])

        entities.append(
            ExtractedEntityRecord(
                entity_type="process",
                entity_value=target_proc_name.lower(),
                role="target",
                attributes=target_attrs,
            )
        )

    # 4. Network Entities
    if event.network:
        if event.network.source_ip:
            entities.append(
                ExtractedEntityRecord(
                    entity_type="ip",
                    entity_value=event.network.source_ip,
                    role="source",
                    attributes={
                        "port": event.network.source_port,
                        "protocol": event.network.protocol,
                    },
                )
            )
        if event.network.destination_ip:
            entities.append(
                ExtractedEntityRecord(
                    entity_type="ip",
                    entity_value=event.network.destination_ip,
                    role="destination",
                    attributes={
                        "port": event.network.destination_port,
                        "protocol": event.network.protocol,
                    },
                )
            )
        if event.network.destination_hostname:
            entities.append(
                ExtractedEntityRecord(
                    entity_type="domain",
                    entity_value=event.network.destination_hostname.lower(),
                    role="destination_host",
                    attributes={"protocol": event.network.protocol},
                )
            )

    # 5. File Entities
    if event.file:
        if event.file.filename:
            entities.append(
                ExtractedEntityRecord(
                    entity_type="file",
                    entity_value=event.file.filename.lower(),
                    role="target",
                    attributes={
                        "path": event.file.path,
                        "size_bytes": event.file.size_bytes,
                    },
                )
            )
        for algo, hash_val in event.file.hashes.items():
            if hash_val:
                entities.append(
                    ExtractedEntityRecord(
                        entity_type="file_hash",
                        entity_value=hash_val.lower(),
                        role="file_hash",
                        attributes={
                            "algorithm": algo.upper(),
                            "filename": event.file.filename,
                        },
                    )
                )

    # 6. DNS Entities
    if event.dns:
        if event.dns.query_name:
            entities.append(
                ExtractedEntityRecord(
                    entity_type="domain",
                    entity_value=event.dns.query_name.lower().rstrip("."),
                    role="queried_domain",
                    attributes={"query_status": event.dns.query_status},
                )
            )
        for ip in event.dns.resolved_ips:
            entities.append(
                ExtractedEntityRecord(
                    entity_type="ip",
                    entity_value=ip,
                    role="resolved_ip",
                    attributes={"domain": event.dns.query_name},
                )
            )

    # 7. Registry Entities
    if event.registry and event.registry.key_path:
        entities.append(
            ExtractedEntityRecord(
                entity_type="registry",
                entity_value=event.registry.key_path.lower(),
                role="target_key",
                attributes={
                    "value_data": event.registry.value_data,
                    "operation": event.registry.operation,
                },
            )
        )

    return entities
