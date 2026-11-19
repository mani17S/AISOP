# P1-H1 Test Cases: Initial Ingestion Pipeline & Baseline Data Models

| Document Attribute | Specification Details |
|---|---|
| **Document ID** | AISOP-TEST-P1H1-TC |
| **Milestone** | P1-H1: Git Safety Checkpoint & Initial Pipeline Baseline |
| **Checkpoint Commit** | `63bee0b` (`63bee0bd76df3d1c5d9cb8fae1f2ec6ef21f2d`) |
| **Governing ADRs** | [ADR-003: Python Version](docs/03_System_Design/ADR/ADR-003_Python_Version.md), [ADR-004: Ingestion Scope](docs/03_System_Design/ADR/ADR-004_Initial_Ingestion_Scope.md) |
| **Component Scope** | Core Configuration, Cryptographic Hasher, Initial Sysmon Parser, Canonical Schemas, ORM Models |
| **Last Updated** | 2026-09-23 |

---

## 1. Purpose & Scope

This specification defines the functional test cases for **Milestone P1-H1**. P1-H1 established the initial structural baseline of AISOP, including application configuration parsing, deterministic SHA-256 canonical hashing, Sysmon Event ID parsing for process and network events (Event IDs 1, 3, 22), entity extraction, and relational evidence model representations.

---

## 2. Test Case Catalogue

### TC-P1H1-001 — Application Settings Default Values
* **Test ID:** `TC-P1H1-001`
* **Module:** `backend/app/core/config.py`
* **Source Test:** `test_config.py::TestSettingsDefaults::test_app_name_defaults_to_aisop`
* **Objective:** Verify `Settings` loads default parameters correctly when no `.env` file is present.
* **Preconditions:** `Settings(_env_file=None)`.
* **Input:** Default class instantiation.
* **Expected Result:** `settings.APP_NAME == "AISOP"`, `settings.APP_VERSION == "0.1.0"`, `settings.DATABASE_URL.startswith("postgresql")`.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-002 — Application Settings Environment Overrides
* **Test ID:** `TC-P1H1-002`
* **Module:** `backend/app/core/config.py`
* **Source Test:** `test_config.py::TestSettingsOverrides::test_debug_overridden_by_env_var`
* **Objective:** Verify environment variables override application configuration defaults.
* **Preconditions:** Monkeypatch environment variable `DEBUG="true"`.
* **Input:** `Settings(_env_file=None)`.
* **Expected Result:** `settings.DEBUG is True`.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-003 — Settings Enum Validation & Rejection
* **Test ID:** `TC-P1H1-003`
* **Module:** `backend/app/core/config.py`
* **Source Test:** `test_config.py::TestSettingsValidation::test_invalid_environment_is_rejected`
* **Objective:** Verify invalid environment string choices are rejected by Pydantic.
* **Preconditions:** Monkeypatch `ENVIRONMENT="banana"`.
* **Input:** `Settings(_env_file=None)`.
* **Expected Result:** `pytest.raises(Exception)` due to invalid Literal validation.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-004 — Settings Singleton Cache Behavior
* **Test ID:** `TC-P1H1-004`
* **Module:** `backend/app/core/config.py`
* **Source Test:** `test_config.py::TestGetSettings::test_returns_same_instance_on_repeated_calls`
* **Objective:** Verify `get_settings()` caches the settings object as a singleton.
* **Preconditions:** Invocation of `get_settings()`.
* **Input:** Repeated invocations of `get_settings()`.
* **Expected Result:** `first is second`.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-005 — Hasher Determinism Across Dictionary Key Orderings
* **Test ID:** `TC-P1H1-005`
* **Module:** `backend/app/modules/evidence/hasher.py`
* **Source Test:** `test_hasher.py::test_hasher_deterministic_for_dict_key_ordering`
* **Objective:** Verify that two dictionaries with identical keys in different orders produce the identical SHA-256 hash.
* **Preconditions:** Two dictionaries `{"a": 1, "b": 2}` and `{"b": 2, "a": 1}`.
* **Input:** `sha256_canonical(dict_a)` and `sha256_canonical(dict_b)`.
* **Expected Result:** Hash digests are byte-for-byte identical.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-006 — Hasher Collision Differentiation
* **Test ID:** `TC-P1H1-006`
* **Module:** `backend/app/modules/evidence/hasher.py`
* **Source Test:** `test_hasher.py::test_hasher_different_content_produces_different_hash`
* **Objective:** Verify distinct payloads produce distinct SHA-256 hashes.
* **Preconditions:** Two distinct event dictionaries.
* **Input:** `sha256_canonical(payload_1)` and `sha256_canonical(payload_2)`.
* **Expected Result:** `hash1 != hash2`.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-007 — Compact Canonical JSON Formatting
* **Test ID:** `TC-P1H1-007`
* **Module:** `backend/app/modules/evidence/hasher.py`
* **Source Test:** `test_hasher.py::test_canonicalize_payload_json`
* **Objective:** Verify `canonicalize_payload` sorts keys and uses compact separators `(',', ':')`.
* **Preconditions:** Nested JSON payload with whitespace.
* **Input:** `canonicalize_payload(data)`.
* **Expected Result:** Formatted string contains sorted keys without extraneous whitespace.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-008 — Canonical Event Schema Instantiation
* **Test ID:** `TC-P1H1-008`
* **Module:** `backend/app/schemas/canonical_event.py`
* **Source Test:** `test_canonical_schema.py::test_canonical_event_defaults`
* **Objective:** Verify `CanonicalEvent` initializes with default UUID and UTC timestamp.
* **Preconditions:** Valid event payload.
* **Input:** `CanonicalEvent(event_type="process_creation", source_type="sysmon")`.
* **Expected Result:** Event contains valid UUIDv4 `id` and non-null `event_timestamp`.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-009 — Sysmon Parser: Event ID 1 (Process Creation)
* **Test ID:** `TC-P1H1-009`
* **Module:** `backend/app/modules/evidence/sysmon_parser.py`
* **Source Test:** `test_sysmon_parser.py::test_sysmon_event_1_process_creation`
* **Objective:** Verify normalization of Sysmon Event ID 1 into `ProcessEntity` and parent process details.
* **Preconditions:** Sysmon Event ID 1 JSON dictionary (`cmd.exe` spawned by `explorer.exe`).
* **Input:** `parser.parse(raw_event)`.
* **Expected Result:** `event.event_type == "process_creation"`, `event.process.process_name == "cmd.exe"`, `event.process.parent_process_name == "explorer.exe"`.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-010 — Sysmon Parser: Event ID 3 (Network Connection)
* **Test ID:** `TC-P1H1-010`
* **Module:** `backend/app/modules/evidence/sysmon_parser.py`
* **Source Test:** `test_sysmon_parser.py::test_sysmon_event_3_network_connection`
* **Objective:** Verify normalization of Sysmon Event ID 3 into `NetworkEntity`.
* **Preconditions:** Sysmon Event ID 3 JSON dictionary.
* **Input:** `parser.parse(raw_event)`.
* **Expected Result:** `event.network.destination_ip == "192.168.1.50"`, `event.network.destination_port == 443`, `event.network.protocol == "tcp"`.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-011 — Sysmon Parser: Event ID 22 (DNS Query)
* **Test ID:** `TC-P1H1-011`
* **Module:** `backend/app/modules/evidence/sysmon_parser.py`
* **Source Test:** `test_sysmon_parser.py::test_sysmon_event_22_dns_query`
* **Objective:** Verify normalization of Sysmon Event ID 22 into `DnsEntity`.
* **Preconditions:** Sysmon Event ID 22 JSON dictionary with query name and results.
* **Input:** `parser.parse(raw_event)`.
* **Expected Result:** `event.dns.query_name == "malicious.example.com"`, `event.dns.query_results` contains resolved IP.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-012 — Entity Extractor: Process Observables
* **Test ID:** `TC-P1H1-012`
* **Module:** `backend/app/modules/evidence/entity_extractor.py`
* **Source Test:** `test_entity_extractor.py::test_extract_entities_from_process_event`
* **Objective:** Verify discrete entity generation (`process`, `user`, `host`, `file_hash`) from process event.
* **Preconditions:** Canonical process event.
* **Input:** `extract_entities(canonical_event)`.
* **Expected Result:** Returns list of `ExtractedEntityItem` instances mapping executable name, hash, and user.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-013 — Entity Extractor: Network Observables
* **Test ID:** `TC-P1H1-013`
* **Module:** `backend/app/modules/evidence/entity_extractor.py`
* **Source Test:** `test_entity_extractor.py::test_extract_entities_from_network_event`
* **Objective:** Verify discrete entity generation (`ip`) with role differentiation (`source`, `destination`).
* **Preconditions:** Canonical network event.
* **Input:** `extract_entities(canonical_event)`.
* **Expected Result:** Contains IP entities with `role="source"` and `role="destination"`.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-014 — ORM Evidence Models CRUD
* **Test ID:** `TC-P1H1-014`
* **Module:** `backend/app/models/evidence.py`
* **Source Test:** `test_evidence_models.py::test_raw_evidence_crud`
* **Objective:** Verify persistence and retrieval of `RawEvidence` model.
* **Preconditions:** Database session.
* **Input:** Insert `RawEvidence(sha256_hash="...", raw_payload={...})`.
* **Expected Result:** Record committed and queried back with matching hash and payload.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-015 — Initial Ingestion Batch Execution
* **Test ID:** `TC-P1H1-015`
* **Module:** `backend/app/services/ingestion_service.py`
* **Source Test:** `test_ingestion_service.py::test_ingest_batch_success`
* **Objective:** Verify end-to-end processing of a batch of raw Sysmon events into database.
* **Preconditions:** In-memory session.
* **Input:** `IngestRequest` containing two valid Sysmon events.
* **Expected Result:** `response.total_received == 2`, `response.total_normalized == 2`, `response.total_skipped_duplicates == 0`.
* **Status:** PASS (Reconstructed from commit `63bee0b`).

---

### TC-P1H1-016 — End-to-End Attack Chain Sample Ingestion
* **Test ID:** `TC-P1H1-016`
* **Module:** `backend/tests/unit/test_sample_dataset_ingestion.py`
* **Source Test:** `test_sample_dataset_ingestion.py::test_ingest_attack_chain_dataset`
* **Objective:** Verify ingestion of multi-stage synthetic attack chain fixture (`sysmon_attack_chain.json`).
* **Preconditions:** Sample dataset file present in repository.
* **Input:** Load and ingest JSON attack chain.
* **Expected Result:** All attack chain events parsed, normalized, and persisted without errors.
* **Status:** PASS (Reconstructed from commit `63bee0b`).
