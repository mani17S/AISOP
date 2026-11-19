# P1-H8 Test Cases: Expanded Sysmon Parser & Entity Extraction

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H8-TC |
| **Milestone** | P1-H8: Expanded Sysmon Parser Coverage (Event IDs 8, 10, 15, 23) |
| **Checkpoint Commit** | `e5ffff8` (`e5ffff892109760185a3073e288ccbbbd6dd3e5a`) |
| **Governing SRS / ADR** | ADR-004: Ingestion Scope, Canonical Schema Model |
| **Component Scope** | Sysmon Parser (`app/modules/evidence/sysmon_parser.py`), Entity Extractor (`app/modules/evidence/entity_extractor.py`) |
| **Last Updated** | 2026-09-23 |

---

## 1. Purpose & Scope

This document specifies the test cases for **Milestone P1-H8**. Milestone P1-H8 expanded the evidence parsing engine beyond process execution, network connections, and DNS lookups to cover advanced attacker techniques:
1. **Sysmon Event ID 8 (CreateRemoteThread):** Detects process injection and code injection (T1055).
2. **Sysmon Event ID 10 (ProcessAccess):** Detects credential dumping and suspicious process memory access (e.g., `lsass.exe` inspection, T1003).
3. **Sysmon Event ID 15 (FileCreateStreamHash):** Detects Alternate Data Stream (ADS) creation and downloaded payload zone identification (T1564.004).
4. **Sysmon Event ID 23 (FileDelete):** Preserves forensic evidence and hashes of deleted attacker binaries (T1070.004) without taking destructive actions.
5. **Robust Normalization & Edge Cases:** Fallback timestamp handling, bare-hash pattern auto-detection, boolean token normalization, and negative heuristic parsing.

---

## 2. Test Case Catalogue

### TC-P1H8-001 — Sysmon Heuristic Detection for New Event IDs
* **Test ID:** `TC-P1H8-001`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_can_parse_new_events`
* **Objective:** Verify `can_parse()` identifies payloads for Event IDs 8, 10, 15, and 23.
* **Preconditions:** Sysmon JSON payloads with valid Event IDs and characteristic field signatures.
* **Input:** Sample payloads for Events 8, 10, 15, and 23.
* **Expected Result:** `parser.can_parse(payload) is True` for all four types.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-002 — Event ID 8 CreateRemoteThread Normalization
* **Test ID:** `TC-P1H8-002`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_event_8_create_remote_thread`
* **Objective:** Parse Sysmon Event 8 into canonical event with source and target process attributes, new thread ID, and start function.
* **Preconditions:** Fixture `sysmon_create_remote_thread.json`.
* **Input:** `powershell.exe` (PID 5412) injecting thread into `notepad.exe` (PID 1024).
* **Expected Result:** `event_type == "create_remote_thread"`, `action == "injected"`, `severity == "high"`, source and target process contexts preserved.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-003 — Event ID 10 ProcessAccess Normalization
* **Test ID:** `TC-P1H8-003`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_event_10_process_access`
* **Objective:** Parse Sysmon Event 10 into canonical event capturing granted access mask and call trace.
* **Preconditions:** Fixture `sysmon_process_access.json`.
* **Input:** `taskmgr.exe` opening handle to `lsass.exe` with access mask `0x1010`.
* **Expected Result:** `event_type == "process_access"`, `action == "accessed"`, `severity == "medium"`, `granted_access == "0x1010"`, call trace captured in custom fields.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-004 — Event ID 15 FileCreateStreamHash Normalization
* **Test ID:** `TC-P1H8-004`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_event_15_file_create_stream_hash`
* **Objective:** Parse Sysmon Event 15 capturing Alternate Data Stream paths, hashes, and creating process.
* **Preconditions:** Fixture `sysmon_file_create_stream_hash.json`.
* **Input:** `browser.exe` creating `invoice.pdf:Zone.Identifier`.
* **Expected Result:** `event_type == "file_create_stream_hash"`, `action == "created"`, `file.filename == "invoice.pdf:Zone.Identifier"`, SHA256 and MD5 hashes parsed.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-005 — Event ID 23 FileDelete Normalization
* **Test ID:** `TC-P1H8-005`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_event_23_file_delete`
* **Objective:** Parse Sysmon Event 23 recording deletion of attacker tools while maintaining non-destructive evidence handling.
* **Preconditions:** Fixture `sysmon_file_delete.json`.
* **Input:** `powershell.exe` deleting `C:\Users\Public\mimikatz.exe`.
* **Expected Result:** `event_type == "file_delete"`, `action == "deleted"`, `severity == "informational"`, SHA256 preserved, `is_executable == True`.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-006 — Missing Optional Fields Graceful Handling
* **Test ID:** `TC-P1H8-006`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_missing_optional_fields_safety`
* **Objective:** Ensure parser does not throw `KeyError` or crash when optional fields are omitted in Events 8, 10, 15, and 23.
* **Preconditions:** Minimal payloads with only essential identity fields.
* **Input:** Minimal event dictionaries.
* **Expected Result:** Events normalize cleanly with missing custom fields set to `None`.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-007 — Bare Hash Detection Without Explicit Key
* **Test ID:** `TC-P1H8-007`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_bare_hash_detection`
* **Objective:** Infer hash algorithm (SHA256, MD5, SHA1) based on character length and hexadecimal pattern when prefix key is missing.
* **Preconditions:** Unlabeled hex strings of length 64, 32, and 40.
* **Input:** `"17565fe8..."` (64 chars), `"90015098..."` (32 chars), `"2aae6c35..."` (40 chars).
* **Expected Result:** Auto-detected as `"SHA256"`, `"MD5"`, and `"SHA1"`.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-008 — Boolean String Normalization
* **Test ID:** `TC-P1H8-008`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_boolean_normalization`
* **Objective:** Convert arbitrary boolean representations ("true", "1", "yes", "0", "false", None) to Python bools.
* **Preconditions:** Various string and integer inputs.
* **Input:** Truthy and falsy strings.
* **Expected Result:** Accurate `True`, `False`, or `None` return values.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-009 — Unsupported Event ID Fallback Normalization
* **Test ID:** `TC-P1H8-009`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_unsupported_event_id_fallback`
* **Objective:** Gracefully handle unmapped Sysmon event IDs (e.g., Event ID 99) by generating generic canonical event.
* **Preconditions:** Payload with `EventID: 99`.
* **Input:** `{"EventID": 99, "ProcessId": 1234, "Image": "something.exe"}`.
* **Expected Result:** `event_type == "sysmon_event_99"`, `action == "observed"`, PID preserved.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-010 — Invalid Timestamp Graceful Fallback
* **Test ID:** `TC-P1H8-010`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_invalid_timestamp_graceful_fallback`
* **Objective:** Prevent ingestion crashes when event timestamps are corrupt or non-standard ISO strings.
* **Preconditions:** Payload with `UtcTime: "invalid-timestamp-value"`.
* **Input:** Malformed timestamp string.
* **Expected Result:** Parser falls back to valid UTC datetime without raising exceptions.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-011 — Negative Heuristic Parsing Cases
* **Test ID:** `TC-P1H8-011`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_can_parse_negative_cases`
* **Objective:** Reject non-Sysmon logs (Windows Security 4624, Zeek network logs, empty dictionaries).
* **Preconditions:** Payloads lacking Sysmon signatures.
* **Input:** Non-Sysmon dictionaries and empty payloads.
* **Expected Result:** `can_parse()` returns `False`.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-012 — Malformed Hash Edge Case Filtering
* **Test ID:** `TC-P1H8-012`
* **Module:** `backend/tests/unit/test_sysmon_parser.py`
* **Source Test:** `test_sysmon_hash_parsing_edge_cases`
* **Objective:** Reject non-hex strings, unsupported length hex tokens, and empty key-value pairs in hash strings.
* **Preconditions:** Malformed hash inputs (`"g"*64`, `"=value"`, `"key="`).
* **Input:** Various invalid hash formats.
* **Expected Result:** Return `{}` without parsing errors.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-013 — Dual Process Extraction for Remote Thread Events
* **Test ID:** `TC-P1H8-013`
* **Module:** `backend/tests/unit/test_entity_extractor.py`
* **Source Test:** `test_extract_entities_from_remote_thread_event`
* **Objective:** Extract both source (`powershell.exe`) and target (`notepad.exe`) process entities with differentiated roles.
* **Preconditions:** Parsed Event 8 canonical model.
* **Input:** Remote thread event.
* **Expected Result:** Two process entities extracted with `role == "source"` and `role == "target"`, including PID and thread attributes.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-014 — Dual Process Extraction for Process Access Events
* **Test ID:** `TC-P1H8-014`
* **Module:** `backend/tests/unit/test_entity_extractor.py`
* **Source Test:** `test_extract_entities_from_process_access_event`
* **Objective:** Extract accessor and target process entities along with granted access mask.
* **Preconditions:** Parsed Event 10 canonical model.
* **Input:** Process access event (`taskmgr.exe` accessing `lsass.exe`).
* **Expected Result:** Two process entities with `role == "source"` and `role == "target"`, target containing `granted_access == "0x1010"`.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-015 — Entity Extraction from Stream & File Delete Events
* **Test ID:** `TC-P1H8-015`
* **Module:** `backend/tests/unit/test_entity_extractor.py`
* **Source Test:** `test_extract_entities_from_file_stream_and_delete_events`
* **Objective:** Extract file and file_hash entities from Alternate Data Stream and deletion events.
* **Preconditions:** Parsed Event 15 and Event 23 canonical models.
* **Input:** ADS creation and file deletion events.
* **Expected Result:** File entities normalized to lowercase; SHA256 hashes extracted as `file_hash` entities.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).

---

### TC-P1H8-016 — Ingestion Service Fixture Pipeline for New Events
* **Test ID:** `TC-P1H8-016`
* **Module:** `backend/tests/unit/test_sample_dataset_ingestion.py`
* **Source Test:** `test_ingest_p1_h8_new_sysmon_events_dataset`
* **Objective:** Ingest all 4 new Sysmon fixtures through full ingestion pipeline, verify entity extraction, and verify duplicate batch deduplication.
* **Preconditions:** IngestionService and in-memory database session.
* **Input:** Batch of 4 events (`sysmon_create_remote_thread.json`, `sysmon_process_access.json`, `sysmon_file_create_stream_hash.json`, `sysmon_file_delete.json`).
* **Expected Result:**
  * Pass 1: `total_received == 4`, `total_normalized == 4`, `total_skipped_duplicates == 0`.
  * Pass 2: `total_received == 4`, `total_normalized == 0`, `total_skipped_duplicates == 4`.
* **Classification:** Test Specification (Reconstructed from commit `e5ffff8`).
