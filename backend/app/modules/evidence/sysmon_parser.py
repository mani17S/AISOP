"""
AISOP Sysmon JSON Parser.

Implements ADR-004:
Sysmon provides rich endpoint telemetry for SOC/Blue Team investigation:
- Event ID 1: Process Creation
- Event ID 3: Network Connection
- Event ID 7: Image Loaded (DLL)
- Event ID 8: CreateRemoteThread
- Event ID 10: ProcessAccess
- Event ID 11: File Creation
- Event ID 12/13/14: Registry Event
- Event ID 15: FileCreateStreamHash
- Event ID 22: DNS Query
- Event ID 23: FileDelete

Handles both nested Windows Event Log JSON structures and flat JSON records.
Note: Binary EVTX parsing is out of scope; telemetry must be in JSON representation.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from app.modules.evidence.hasher import compute_sha256
from app.schemas.entities import (
    DnsEntity,
    FileEntity,
    HostEntity,
    NetworkEntity,
    ProcessEntity,
    RegistryEntity,
    UserEntity,
)
from app.schemas.normalized_event import CanonicalEvent


class SysmonParser:
    """Parser for Sysmon telemetry in JSON format."""

    def parser_name(self) -> str:
        return "sysmon"

    def can_parse(self, raw_data: dict[str, Any] | str) -> bool:
        """
        Inspect whether this record is a Sysmon event.
        """
        data = self._ensure_dict(raw_data)
        if not data:
            return False

        # Look for Sysmon provider or typical Sysmon fields
        provider = self._find_case_insensitive(
            data, ["Provider", "provider", "Channel", "channel"]
        )
        if provider and "sysmon" in str(provider).lower():
            return True

        # Check for nested Windows Event structure
        system = data.get("Event", {}).get("System", {})
        if system:
            prov_name = system.get("Provider", {}).get("@Name", "")
            if "sysmon" in prov_name.lower():
                return True

        # Check for signature Sysmon field combinations
        has_event_id = (
            self._find_case_insensitive(data, ["EventID", "event_id", "EventId"])
            is not None
        )
        has_sysmon_fields = any(
            self._find_case_insensitive(data, [field]) is not None
            for field in [
                "ProcessGuid",
                "ParentProcessGuid",
                "SourceProcessGuid",
                "SourceProcessGUID",
                "TargetProcessGuid",
                "TargetProcessGUID",
                "ImageLoaded",
                "DestinationIp",
                "QueryName",
                "GrantedAccess",
                "CallTrace",
                "TargetFilename",
            ]
        )
        return has_event_id and has_sysmon_fields

    def parse(
        self,
        raw_data: dict[str, Any] | str,
        raw_ref: str | None = None,
    ) -> list[CanonicalEvent]:
        """
        Transform raw Sysmon record into a CanonicalEvent.
        """
        data = self._ensure_dict(raw_data)
        if not data:
            return []

        if raw_ref is None:
            raw_ref = compute_sha256(raw_data)

        # Flatten nested structures if present
        flattened = self._flatten_event(data)

        event_id_val = self._find_case_insensitive(
            flattened, ["EventID", "event_id", "EventId"]
        )
        event_id_str = str(event_id_val) if event_id_val is not None else "0"

        # Timestamp extraction
        timestamp = self._parse_timestamp(flattened)

        # Host extraction
        host = self._extract_host(flattened)

        # User extraction
        user = self._extract_user(flattened)

        # Specialized parsing based on Event ID
        event_type = "unknown"
        action = "observed"
        process: ProcessEntity | None = None
        network: NetworkEntity | None = None
        file_ent: FileEntity | None = None
        registry: RegistryEntity | None = None
        dns: DnsEntity | None = None

        if event_id_str == "1":
            event_type = "process_creation"
            action = "started"
            process = self._parse_event_1_process(flattened)
        elif event_id_str == "3":
            event_type = "network_connection"
            action = "connected"
            network = self._parse_event_3_network(flattened)
            process = self._parse_process_context(flattened)
        elif event_id_str == "7":
            event_type = "image_load"
            action = "loaded"
            file_ent = self._parse_event_7_image(flattened)
            process = self._parse_process_context(flattened)
        elif event_id_str == "8":
            event_type = "create_remote_thread"
            action = "created"
            process = self._parse_event_8_source_process(flattened)
            self._enrich_event_8_custom_fields(flattened)
        elif event_id_str == "10":
            event_type = "process_access"
            action = "accessed"
            process = self._parse_event_10_source_process(flattened)
            self._enrich_event_10_custom_fields(flattened)
        elif event_id_str == "11":
            event_type = "file_create"
            action = "created"
            file_ent = self._parse_event_11_file(flattened)
            process = self._parse_process_context(flattened)
        elif event_id_str in ("12", "13", "14"):
            event_type = "registry_event"
            action = "modified"
            registry = self._parse_event_registry(flattened)
            process = self._parse_process_context(flattened)
        elif event_id_str == "15":
            event_type = "file_create_stream_hash"
            action = "created"
            file_ent = self._parse_event_15_stream_hash(flattened)
            process = self._parse_process_context(flattened)
            creation_utc = self._find_case_insensitive(
                flattened, ["CreationUtcTime", "creation_utc_time"]
            )
            if creation_utc:
                flattened["creation_utc_time"] = str(creation_utc)
        elif event_id_str == "22":
            event_type = "dns_query"
            action = "queried"
            dns = self._parse_event_22_dns(flattened)
            process = self._parse_process_context(flattened)
        elif event_id_str == "23":
            event_type = "file_delete"
            action = "deleted"
            file_ent = self._parse_event_23_file_delete(flattened)
            process = self._parse_process_context(flattened)
            self._enrich_event_23_custom_fields(flattened)
        else:
            event_type = f"sysmon_event_{event_id_str}"
            process = self._parse_process_context(flattened)

        canonical = CanonicalEvent(
            event_id=event_id_str,
            event_type=event_type,
            timestamp=timestamp,
            provider="Microsoft-Windows-Sysmon",
            action=action,
            outcome="success",
            severity="informational",
            host=host,
            user=user,
            process=process,
            network=network,
            file=file_ent,
            registry=registry,
            dns=dns,
            raw_ref=raw_ref,
            custom_fields=flattened,
        )

        return [canonical]

    def _ensure_dict(self, raw_data: dict[str, Any] | str) -> dict[str, Any]:
        if isinstance(raw_data, dict):
            return raw_data
        if isinstance(raw_data, str):
            try:
                parsed = json.loads(raw_data)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return {}
        return {}

    def _flatten_event(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract all keys into a single top-level map, merging EventData and System."""
        flat: dict[str, Any] = {}
        flat.update(data)

        # Check standard Windows XML-to-JSON structures
        event_block = data.get("Event", {})
        if isinstance(event_block, dict):
            system_block = event_block.get("System", {})
            if isinstance(system_block, dict):
                flat.update(system_block)
            data_block = event_block.get("EventData", {})
            if isinstance(data_block, dict):
                flat.update(data_block)

        # Handle top-level EventData
        data_block2 = data.get("EventData", {})
        if isinstance(data_block2, dict):
            flat.update(data_block2)

        return flat

    def _find_case_insensitive(
        self, data: dict[str, Any], candidates: list[str]
    ) -> Any | None:
        lowered_map = {k.lower(): v for k, v in data.items()}
        for cand in candidates:
            cand_lower = cand.lower()
            if cand_lower in lowered_map and lowered_map[cand_lower] is not None:
                return lowered_map[cand_lower]
        return None

    def _parse_timestamp(self, data: dict[str, Any]) -> datetime:
        candidates = [
            "UtcTime",
            "utctime",
            "TimeCreated",
            "time_created",
            "timestamp",
            "@timestamp",
        ]
        ts_val = self._find_case_insensitive(data, candidates)

        if isinstance(ts_val, dict) and "@SystemTime" in ts_val:
            ts_val = ts_val["@SystemTime"]

        if isinstance(ts_val, str) and ts_val.strip():
            cleaned = ts_val.strip().replace(" ", "T")
            try:
                dt = datetime.fromisoformat(cleaned)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                pass

        return datetime.now(timezone.utc)

    def _extract_host(self, data: dict[str, Any]) -> HostEntity | None:
        hostname = self._find_case_insensitive(
            data, ["Computer", "computer", "hostname", "HostName", "host"]
        )
        if not hostname:
            return None
        return HostEntity(hostname=str(hostname))

    def _extract_user(self, data: dict[str, Any]) -> UserEntity | None:
        raw_user = self._find_case_insensitive(
            data, ["User", "user", "UserName", "username"]
        )
        if not raw_user:
            return None

        user_str = str(raw_user)
        domain = None
        username = user_str

        if "\\" in user_str:
            parts = user_str.split("\\", 1)
            domain = parts[0]
            username = parts[1]
        elif "@" in user_str:
            parts = user_str.split("@", 1)
            username = parts[0]
            domain = parts[1]

        sid = self._find_case_insensitive(data, ["UserSid", "user_sid", "SecurityID"])
        logon_id = self._find_case_insensitive(
            data, ["LogonId", "logon_id", "LogonGuid"]
        )

        return UserEntity(
            username=username,
            domain=domain,
            sid=str(sid) if sid else None,
            logon_id=str(logon_id) if logon_id else None,
        )

    def _parse_hashes(self, hash_str: Any) -> dict[str, str]:
        """Parse Sysmon hashes string e.g. 'SHA256=ABC...,MD5=DEF...' or bare hex hash."""
        if not hash_str or not isinstance(hash_str, str):
            return {}
        hashes: dict[str, str] = {}
        tokens = re.split(r"[,;]\s*", hash_str.strip())
        for token in tokens:
            if "=" in token:
                k, v = token.split("=", 1)
                k_clean = k.strip().upper()
                v_clean = v.strip()
                if k_clean and v_clean:
                    hashes[k_clean] = v_clean
            else:
                clean_token = token.strip()
                if clean_token and re.fullmatch(r"[0-9a-fA-F]+", clean_token):
                    # Bare hex hash: detect algorithm by character length
                    algo_map = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}
                    algo = algo_map.get(len(clean_token))
                    if algo:
                        hashes[algo] = clean_token
        return hashes

    def _parse_bool(self, val: Any) -> bool | None:
        """Deterministically normalize boolean-like fields (true/false, 1/0, yes/no)."""
        if val is None:
            return None
        if isinstance(val, bool):
            return val
        s = str(val).strip().lower()
        if s in ("true", "1", "yes"):
            return True
        if s in ("false", "0", "no"):
            return False
        return None

    def _parse_int(self, val: Any) -> int | None:
        if val is None:
            return None
        try:
            return int(str(val), 0)  # Handles both decimal and hex '0x123'
        except Exception:
            return None

    def _parse_event_1_process(self, data: dict[str, Any]) -> ProcessEntity:
        image = self._find_case_insensitive(data, ["Image", "image"])
        cmd = self._find_case_insensitive(data, ["CommandLine", "command_line"])
        pid = self._parse_int(
            self._find_case_insensitive(data, ["ProcessId", "process_id", "PID"])
        )
        ppid = self._parse_int(
            self._find_case_insensitive(
                data, ["ParentProcessId", "parent_process_id", "PPID"]
            )
        )
        parent_image = self._find_case_insensitive(
            data, ["ParentImage", "parent_image"]
        )
        parent_cmd = self._find_case_insensitive(
            data, ["ParentCommandLine", "parent_command_line"]
        )
        proc_guid = self._find_case_insensitive(data, ["ProcessGuid", "process_guid"])
        parent_guid = self._find_case_insensitive(
            data, ["ParentProcessGuid", "parent_process_guid"]
        )
        curr_dir = self._find_case_insensitive(
            data, ["CurrentDirectory", "current_directory"]
        )
        integrity = self._find_case_insensitive(
            data, ["IntegrityLevel", "integrity_level"]
        )
        raw_user = self._find_case_insensitive(data, ["User", "user"])
        hashes = self._parse_hashes(
            self._find_case_insensitive(data, ["Hashes", "hashes", "Hash", "hash"])
        )

        proc_name = None
        if image and isinstance(image, str):
            proc_name = image.split("\\")[-1].split("/")[-1]

        return ProcessEntity(
            image_path=str(image) if image else None,
            process_name=proc_name,
            command_line=str(cmd) if cmd else None,
            pid=pid,
            ppid=ppid,
            parent_image=str(parent_image) if parent_image else None,
            parent_command_line=str(parent_cmd) if parent_cmd else None,
            process_guid=str(proc_guid) if proc_guid else None,
            parent_process_guid=str(parent_guid) if parent_guid else None,
            current_directory=str(curr_dir) if curr_dir else None,
            integrity_level=str(integrity) if integrity else None,
            user=str(raw_user) if raw_user else None,
            hashes=hashes,
        )

    def _parse_event_3_network(self, data: dict[str, Any]) -> NetworkEntity:
        src_ip = self._find_case_insensitive(
            data, ["SourceIp", "source_ip", "SourceIP"]
        )
        src_port = self._parse_int(
            self._find_case_insensitive(
                data, ["SourcePort", "source_port", "SourcePort"]
            )
        )
        dest_ip = self._find_case_insensitive(
            data, ["DestinationIp", "destination_ip", "DestinationIP"]
        )
        dest_port = self._parse_int(
            self._find_case_insensitive(data, ["DestinationPort", "destination_port"])
        )
        proto = self._find_case_insensitive(data, ["Protocol", "protocol"])
        dest_host = self._find_case_insensitive(
            data, ["DestinationHostname", "destination_hostname"]
        )
        initiated = self._find_case_insensitive(data, ["Initiated", "initiated"])

        is_initiated = self._parse_bool(initiated)

        return NetworkEntity(
            source_ip=str(src_ip) if src_ip else None,
            source_port=src_port,
            destination_ip=str(dest_ip) if dest_ip else None,
            destination_port=dest_port,
            protocol=str(proto).lower() if proto else None,
            destination_hostname=str(dest_host) if dest_host else None,
            direction="outbound" if is_initiated else "inbound",
            initiated=is_initiated,
        )

    def _parse_event_7_image(self, data: dict[str, Any]) -> FileEntity:
        image_loaded = self._find_case_insensitive(
            data, ["ImageLoaded", "image_loaded"]
        )
        hashes = self._parse_hashes(
            self._find_case_insensitive(data, ["Hashes", "hashes", "Hash", "hash"])
        )

        filename = None
        if image_loaded and isinstance(image_loaded, str):
            filename = image_loaded.split("\\")[-1].split("/")[-1]

        return FileEntity(
            path=str(image_loaded) if image_loaded else None,
            filename=filename,
            hashes=hashes,
        )

    def _parse_event_8_source_process(self, data: dict[str, Any]) -> ProcessEntity:
        src_image = self._find_case_insensitive(
            data, ["SourceImage", "source_image", "Image", "image"]
        )
        src_pid = self._parse_int(
            self._find_case_insensitive(
                data, ["SourceProcessId", "source_process_id", "ProcessId", "PID"]
            )
        )
        src_guid = self._find_case_insensitive(
            data,
            [
                "SourceProcessGuid",
                "source_process_guid",
                "SourceProcessGUID",
                "ProcessGuid",
                "process_guid",
            ],
        )
        raw_user = self._find_case_insensitive(data, ["User", "user"])

        proc_name = None
        if src_image and isinstance(src_image, str):
            proc_name = src_image.split("\\")[-1].split("/")[-1]

        return ProcessEntity(
            image_path=str(src_image) if src_image else None,
            process_name=proc_name,
            pid=src_pid,
            process_guid=str(src_guid) if src_guid else None,
            user=str(raw_user) if raw_user else None,
        )

    def _enrich_event_8_custom_fields(self, data: dict[str, Any]) -> None:
        target_image = self._find_case_insensitive(
            data, ["TargetImage", "target_image"]
        )
        target_pid = self._parse_int(
            self._find_case_insensitive(data, ["TargetProcessId", "target_process_id"])
        )
        target_guid = self._find_case_insensitive(
            data, ["TargetProcessGuid", "target_process_guid", "TargetProcessGUID"]
        )
        new_thread_id = self._parse_int(
            self._find_case_insensitive(data, ["NewThreadId", "new_thread_id"])
        )
        start_addr = self._find_case_insensitive(
            data, ["StartAddress", "start_address"]
        )
        start_mod = self._find_case_insensitive(data, ["StartModule", "start_module"])
        start_func = self._find_case_insensitive(
            data, ["StartFunction", "start_function"]
        )

        if target_image:
            target_name = str(target_image).split("\\")[-1].split("/")[-1]
            data["target_process_name"] = target_name
            data["target_image"] = str(target_image)
        if target_pid is not None:
            data["target_process_id"] = target_pid
        if target_guid:
            data["target_process_guid"] = str(target_guid)
        if new_thread_id is not None:
            data["new_thread_id"] = new_thread_id
        if start_addr:
            data["start_address"] = str(start_addr)
        if start_mod:
            data["start_module"] = str(start_mod)
        if start_func:
            data["start_function"] = str(start_func)

    def _parse_event_10_source_process(self, data: dict[str, Any]) -> ProcessEntity:
        src_image = self._find_case_insensitive(
            data, ["SourceImage", "source_image", "Image", "image"]
        )
        src_pid = self._parse_int(
            self._find_case_insensitive(
                data, ["SourceProcessId", "source_process_id", "ProcessId", "PID"]
            )
        )
        src_guid = self._find_case_insensitive(
            data,
            [
                "SourceProcessGUID",
                "source_process_guid",
                "SourceProcessGuid",
                "ProcessGuid",
                "process_guid",
            ],
        )
        raw_user = self._find_case_insensitive(data, ["User", "user"])

        proc_name = None
        if src_image and isinstance(src_image, str):
            proc_name = src_image.split("\\")[-1].split("/")[-1]

        return ProcessEntity(
            image_path=str(src_image) if src_image else None,
            process_name=proc_name,
            pid=src_pid,
            process_guid=str(src_guid) if src_guid else None,
            user=str(raw_user) if raw_user else None,
        )

    def _enrich_event_10_custom_fields(self, data: dict[str, Any]) -> None:
        target_image = self._find_case_insensitive(
            data, ["TargetImage", "target_image"]
        )
        target_pid = self._parse_int(
            self._find_case_insensitive(data, ["TargetProcessId", "target_process_id"])
        )
        target_guid = self._find_case_insensitive(
            data, ["TargetProcessGUID", "target_process_guid", "TargetProcessGuid"]
        )
        src_thread_id = self._parse_int(
            self._find_case_insensitive(data, ["SourceThreadId", "source_thread_id"])
        )
        granted_access = self._find_case_insensitive(
            data, ["GrantedAccess", "granted_access"]
        )
        call_trace = self._find_case_insensitive(data, ["CallTrace", "call_trace"])

        if target_image:
            target_name = str(target_image).split("\\")[-1].split("/")[-1]
            data["target_process_name"] = target_name
            data["target_image"] = str(target_image)
        if target_pid is not None:
            data["target_process_id"] = target_pid
        if target_guid:
            data["target_process_guid"] = str(target_guid)
        if src_thread_id is not None:
            data["source_thread_id"] = src_thread_id
        if granted_access is not None:
            data["granted_access"] = str(granted_access)
        if call_trace is not None:
            data["call_trace"] = str(call_trace)

    def _parse_event_11_file(self, data: dict[str, Any]) -> FileEntity:
        target = self._find_case_insensitive(
            data, ["TargetFilename", "target_filename", "TargetFileName"]
        )
        hashes = self._parse_hashes(
            self._find_case_insensitive(data, ["Hashes", "hashes", "Hash", "hash"])
        )

        filename = None
        if target and isinstance(target, str):
            filename = target.split("\\")[-1].split("/")[-1]

        return FileEntity(
            path=str(target) if target else None,
            filename=filename,
            hashes=hashes,
        )

    def _parse_event_15_stream_hash(self, data: dict[str, Any]) -> FileEntity:
        target = self._find_case_insensitive(
            data, ["TargetFilename", "target_filename", "TargetFileName"]
        )
        hash_val = self._find_case_insensitive(
            data, ["Hash", "hash", "Hashes", "hashes"]
        )
        hashes = self._parse_hashes(hash_val)

        filename = None
        if target and isinstance(target, str):
            filename = target.split("\\")[-1].split("/")[-1]

        return FileEntity(
            path=str(target) if target else None,
            filename=filename,
            hashes=hashes,
        )

    def _parse_event_23_file_delete(self, data: dict[str, Any]) -> FileEntity:
        target = self._find_case_insensitive(
            data, ["TargetFilename", "target_filename", "TargetFileName"]
        )
        hash_val = self._find_case_insensitive(
            data, ["Hashes", "hashes", "Hash", "hash"]
        )
        hashes = self._parse_hashes(hash_val)

        filename = None
        if target and isinstance(target, str):
            filename = target.split("\\")[-1].split("/")[-1]

        return FileEntity(
            path=str(target) if target else None,
            filename=filename,
            hashes=hashes,
        )

    def _enrich_event_23_custom_fields(self, data: dict[str, Any]) -> None:
        is_executable = self._parse_bool(
            self._find_case_insensitive(data, ["IsExecutable", "is_executable"])
        )
        archived = self._parse_bool(
            self._find_case_insensitive(data, ["Archived", "archived"])
        )
        if is_executable is not None:
            data["is_executable"] = is_executable
        if archived is not None:
            data["archived"] = archived

    def _parse_event_registry(self, data: dict[str, Any]) -> RegistryEntity:
        target = self._find_case_insensitive(data, ["TargetObject", "target_object"])
        details = self._find_case_insensitive(data, ["Details", "details"])
        op = self._find_case_insensitive(data, ["EventType", "event_type"])

        return RegistryEntity(
            key_path=str(target) if target else None,
            value_data=str(details) if details else None,
            operation=str(op) if op else None,
        )

    def _parse_event_22_dns(self, data: dict[str, Any]) -> DnsEntity:
        query_name = self._find_case_insensitive(data, ["QueryName", "query_name"])
        query_status = self._find_case_insensitive(
            data, ["QueryStatus", "query_status"]
        )
        query_results = self._find_case_insensitive(
            data, ["QueryResults", "query_results"]
        )

        resolved: list[str] = []
        if query_results and isinstance(query_results, str):
            # Split results by ';' or '::'
            parts = re.split(r"[;,\s]+", query_results)
            resolved = [p.strip() for p in parts if p.strip()]

        return DnsEntity(
            query_name=str(query_name) if query_name else None,
            query_status=str(query_status) if query_status else None,
            resolved_ips=resolved,
        )

    def _parse_process_context(self, data: dict[str, Any]) -> ProcessEntity | None:
        """Extract process info if present on secondary events (e.g. network, DNS, file)."""
        image = self._find_case_insensitive(data, ["Image", "image"])
        pid = self._parse_int(
            self._find_case_insensitive(data, ["ProcessId", "process_id", "PID"])
        )
        cmd = self._find_case_insensitive(data, ["CommandLine", "command_line"])
        guid = self._find_case_insensitive(data, ["ProcessGuid", "process_guid"])
        raw_user = self._find_case_insensitive(data, ["User", "user"])

        if not image and pid is None and not cmd and not guid:
            return None

        proc_name = None
        if image and isinstance(image, str):
            proc_name = image.split("\\")[-1].split("/")[-1]

        return ProcessEntity(
            image_path=str(image) if image else None,
            process_name=proc_name,
            command_line=str(cmd) if cmd else None,
            pid=pid,
            process_guid=str(guid) if guid else None,
            user=str(raw_user) if raw_user else None,
        )
