# Producer-to-canonical field contract (Stage 7A, owner decision D3)

Date: 2026-11-12. Status: IMPLEMENTED for the AISOP evidence envelope (`aisop.evidence/1`); every row below is proven by
`backend/tests/unit/test_stage7a_producer_contract.py` (73 tests, real adapters, no mocks). No adapter code was changed in this milestone:
every mapping already existed (ADR-013 Revision 2) and was only inventoried and proven. Nothing here is inferred from matching strings.

Rule that applies to every row: **a field the source does not state stays absent.** A missing field never becomes a guess, a default
identity, a shared session or a causal link. "Supports X" below means the adapter maps the field AND the detector can use it; it does not
mean the producer emits it.

## 1. Envelope-level fields (all envelope adapters except where noted)

| Canonical field | Native (envelope) field | Transformation and validation | Availability | Proof |
|---|---|---|---|---|
| source system | `source.system` | required string, lower-cased | guaranteed (record rejected without it) | `test_every_type_parses...` |
| source product / adapter | (derived) | `adapter_name@ADAPTER_VERSION` of the adapter selected by `evidence_type` | guaranteed | same |
| native event id | `evidence_id` | bounded string; **provenance only, never a correlation key, never compared across sources** | optional | `test_native_event_ids_are_never_a_correlation_key` |
| provenance | whole record | raw payload preserved unchanged; SHA-256 computed (or attested) | guaranteed | ingestion tests (earlier milestones) |
| event time value | `event_time` | strict parse (`parse_time`); offsets normalised to UTC; never "now" | optional | `test_timestamp_quality_and_timezone_contract` |
| timestamp quality | (derived) | `valid` / `naive_assumed_utc` / `missing` / `invalid` / `out_of_range` | guaranteed (always set) | same |
| timezone | offset in `event_time` | absent offset -> `naive_assumed_utc` (UTC assumed and disclosed); anything else -> UTC | derived | same |
| collection / ingestion time | `collected_at` (source side), storage time (AISOP side) | parsed separately; **never promoted to event time**; storage time lives only in the NOT NULL column and is flagged `event_timestamp_is_ingestion_time` | optional | `test_every_type_parses...`, `test_undated_record_keeps_event_time_unknown...` |
| `upstream_id` (shared lineage) | `source.upstream_id` | validated by `_UPSTREAM_RE`, lower-cased; decides independence only | optional, source-stated | `test_correlation_and_upstream_are_envelope_level...` |
| correlation key | top-level `correlation{issuer,id}` | both required, becomes entity `event_correlation = issuer:id`; one without the other is rejected (`FIELD_MISSING:correlation`) | optional, source-stated; not mapped for `UnclassifiedAdapter` | same, `test_correlation_without_issuer_is_rejected...`, `test_unclassified_records...` |

## 2. Type-specific fields

| Evidence types | Native field(s) | Canonical target | Transformation | Availability | Proof |
|---|---|---|---|---|---|
| `identity.signin`, `identity.mfa`, `cloud.api_call`, `cloud.config_change`, `cloud.object_access` | `session_id` (+ `session_issuer`) | entity `logon_session = <issuer>:<session_id>` | issuer defaults to the record's own `source.system` (so a bare id is local to that system); lower-cased | optional | `test_without_session_issuer_the_session_is_scoped...` |
| same five types | `canonical_id` + `canonical_id_issuer` | entity `principal = <issuer>:<canonical_id>` | both required together (one alone is rejected); **value is case-folded** by the adapter | optional, source-stated | `test_session_issuer_and_canonical_principal_only_where...`, `test_canonical_id_requires_both...` |
| `forensic.file` | `origin_message_id` | relation `file_hash DERIVED_FROM email_message` | lower-cased; only this type | optional, source-stated | `test_origin_message_is_mapped_only_for_forensic_file...` |
| `forensic.file` | `timestamp_semantics` | validated vocabulary `arrival|creation|modification|collection` | bad value rejected (`FIELD_INVALID:timestamp_semantics`) | optional | `test_timestamp_semantics_is_validated...` |
| `identity.privilege_change`, `identity.account_change`, `network.*`, `email.message`, `forensic.registry|memory_finding|process_artifact`, `analyst.observation` | the same session / canonical / origin fields | **none: UNAVAILABLE** (stated by a source, silently not mapped) | none | unavailable | `test_session_issuer_and_canonical_principal_only_where...` (negative branch), origin negative in `test_origin_message...` |
| analyst observation | whole record | `counts_for_corroboration = False`; trust class `analyst_observation` | n/a | guaranteed | earlier milestones |
| unclassified types | `source.upstream_id`, `event_time` | preserved; **no** entities, correlation or classification | n/a | guaranteed | `test_unclassified_records...` |

## 3. Which contradiction kinds each producer can support reliably

A kind needs ALL of its inputs. "Reliable" = the adapter maps every required field and the validation rejects malformed input.

| Kind | Required canonical inputs | Types that can supply them | Not possible from |
|---|---|---|---|
| ordering (causal) | `forensic.file` `origin_message_id` + `timestamp_semantics` in {arrival, creation}; e-mail CONTAINS the same hash; both times valid; independent sources | `forensic.file` + `email.message` | any other pair; a file merely timestamped before an e-mail (D6) |
| outcome | outcome on both records, same proposition, two independent sources, times within 2.0 s | `identity.signin`, `identity.mfa`, `network.firewall`, `network.flow`, `cloud.*` (outcome field) | records with outcome `unknown` (`network.ids`, `email`, `forensic.*`) |
| identity | issuer-scoped `logon_session` AND two different `principal` values of one issuer | `identity.signin`, `identity.mfa`, `cloud.api_call`, `cloud.config_change`, `cloud.object_access` | the other identity types, network, e-mail, forensic |
| temporal | issuer-scoped `event_correlation` on both records, same type/action/outcome, valid times | every non-unclassified envelope type | records without a stated correlation key; source-native ids are never used |
| independence (all kinds) | `source.upstream_id` | every envelope type incl. unclassified | undeclared mirroring: **invisible** (limited to the existing duplicate rules) |

## 4. Legacy alert adapters (ADR-007: Sysmon, Windows Security, generic SIEM, firewall/IDS; cloud audit, EDR, e-mail phishing, Linux auth are registered but not used by the contradiction detector)

| Adapter | Native time field(s) | Canonical handling | Contradiction support |
|---|---|---|---|
| `sysmon` | `System.TimeCreated.@SystemTime`, `EventData.UtcTime`, `timestamp` | adapter substitutes the current time when none parses; `normalize_records` **rejects** such a record (`TIMESTAMP_MISSING_OR_INVALID`) instead of placing it on the timeline | none: no `upstream_id`, `correlation` or canonical principal exists in these formats |
| `windows_security` | `System.TimeCreated.@SystemTime`, `timestamp` | same; `TargetLogonId` (4624) is host-scoped (`host:id`) | none |
| `generic_siem` | `timestamp`, `@timestamp`, `created_at`, `time` | same | none |
| `firewall_ids` | `timestamp`, `@timestamp` | same | none |

Proof: `test_legacy_normalizer_rejects_records_whose_time_the_adapter_would_have_invented` (one generic fixture only). Per-vendor rejection of invented times was NOT re-proven in this milestone (UNVERIFIED beyond that fixture and the adapter source reading above).
Known limitation: a **naive** legacy timestamp is treated as UTC without the `naive_assumed_utc` disclosure that the envelope path gives. Not changed (outside this milestone; no contradiction logic reads these records).

## 5. Gaps and what would be needed to close them (nothing was guessed)

| Gap | To support it later, PROPOSED |
|---|---|
| No native vendor format (CloudTrail, Entra, Zeek, ...) has an adapter; producers must wrap their data in the envelope | per-vendor adapter + vendor documentation + sample fixtures; each native field mapped in this table |
| `canonical_id` case-folding can conflate ids that differ only by case in a case-sensitive directory | confirm per directory whether ids are case-insensitive; if not, an adapter option that preserves case |
| Identity/temporal/ordering findings exist only when the producer emits the optional fields | a producer-side checklist per source (what the vendor actually exposes: e.g. a stable request id for `correlation`, the IdP subject for `canonical_id`) |
| Privilege/account-change events carry no session or principal mapping | evidence that the source states them, then extend `IdentityAdapter` and add fixtures |
| Legacy naive timestamps undisclosed | map to `naive_assumed_utc` in the legacy normalizer, with a test |

---
## Stage 7B addendum (2026-11-12): legacy adapters, identifier case, naive timestamps
Proof: `backend/tests/unit/test_stage7b_legacy_and_identity.py` (57 tests). Earlier sections stay as history except where noted.

### Canonical identifier case (owner decision D4) - supersedes the Stage 7A "case-folded" statement
* `canonical_id` and `correlation.id`: the **identifier keeps its case**. The **issuer** is lower-cased (a system/directory name, like `source.system`).
* One explicit case-insensitive namespace: an identifier in canonical UUID form is folded (RFC 4122 hexadecimal digits are case-insensitive by definition). No other global folding.
* Consequence: `AbC123` and `abc123` of one directory are two principals, so a session attributed to both is an identity contradiction (tested). A producer whose directory is case-insensitive must emit one consistent form (or UUIDs).
* The raw value is preserved in the stored raw payload and in `attributes`; nothing stored is rewritten. Entities are re-derived from the preserved payload at read time, so historical evidence changes only in that derived view.
* Not changed (out of scope, documented): `logon_session` and e-mail/domain/hash/IP entity values remain case-folded by `canonical_entity_value`.

### Legacy alert adapters (all eight in the default registry; one distinct fixture each)
| Adapter | Native time field proven | Naive time | Native id | Entities proven | Identity issuer / principal / upstream / correlation / origin |
|---|---|---|---|---|---|
| `sysmon` | `System.TimeCreated.@SystemTime` (also `EventData.UtcTime`) | UTC by format: not flagged; generic `timestamp` fallback: flagged | `EventID` kept as `source_event_id` (an event TYPE id, not unique) | host, user, process, process_guid, host-scoped `logon_session` | none supplied by the format |
| `windows_security` | `System.TimeCreated.@SystemTime` | UTC by format: not flagged | synthetic `winsec-<eid>-<hash>` on the alert; event id kept as `source_event_id` | host, user, ip, host-scoped `logon_session` | none |
| `linux_auth` | `timestamp` | flagged | `id` kept on the alert (`auth-77`); **not** carried onto the correlation event (gap) | host, ip, process, user | none |
| `edr_malware` | `timestamp` | flagged | `detection_id` kept on the alert; **not** carried onto the correlation event (gap) | host | none |
| `firewall_ids` | `timestamp` | flagged | `signature_id` kept | ip | none |
| `cloud_audit` | `eventTime` | flagged | synthetic `cloud-<hash>` (no native id claimed) | ip, user | none |
| `email_phishing` | `timestamp` | flagged | synthetic `email-<hash>` | domain, user | none |
| `generic_siem` | `timestamp` | flagged | `rule_id` kept | none in the fixture | none |
Common, proven for every row: a missing time is **rejected** (`TIMESTAMP_MISSING_OR_INVALID`), never replaced by "now"; `upstream_id`, `evidence_type`, `principal`, `event_correlation` and `email_message` are never populated; native ids are never entities, and equal id strings in two sources do not link them. Legacy records therefore support **no** identity, temporal, ordering or independence contradiction kind; they take part only in correlation and the sufficiency gate. Fields the fixtures do not carry (for example EDR process data, cloud role names) are not claimed.

### Naive timestamps (owner decision D5) - supersedes the Stage 7A "undisclosed" limitation
* Envelope path: unchanged (`naive_assumed_utc`, rule 3 makes related findings minor; re-tested).
* Legacy path: `CorrelationEvent.time_assumed_utc` is true when the adapter received a time without an offset and the format does not define UTC. It is carried into the context event attributes, the context flag `NAIVE_TIMESTAMPS_ASSUMED_UTC: N ...` and the incident report Limitations line "Time zone assumed". Sysmon `UtcTime` and Windows `@SystemTime` are UTC by format and are not flagged. The raw string is unchanged; the event time is never replaced by ingestion time; no verdict rule was changed (disclosure only).

---
## Stage 7C addendum (2026-11-12): native ids and entity case rules
Proof: `backend/tests/unit/test_stage7c_native_ids_and_entities.py` (23).
* `edr_malware` (`detection_id`) and `linux_auth` (`id`): `CorrelationEvent.native_event_id`, source-scoped by `source_type`, set only when the raw record carries the exact value (never a generated fallback); provenance only, not in `source_event_id`, entities, identity, independence or correlation. Supersedes the Stage 7B "gap" rows for these two adapters.
* Entity case rules (supersede earlier folding statements where they differ): domain / URL host / file hash / process GUID / IP folded; email domain folded, **local part preserved**; message id: only the part after the last `@` folded; envelope session id **preserved** (issuer folded); cloud resource and account **preserved**; principal and correlation ids preserved (UUID-shaped folded). Still folded and an OPEN decision: user names, file paths, registry keys, process names. Full table: `Stage7C_PostgreSQL_Test_Review_Report.md` section 5.
