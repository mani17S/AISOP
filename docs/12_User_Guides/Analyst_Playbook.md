# AISOP Analyst Playbook: running the next investigation

Audience: a SOC analyst working a case in AISOP. Scope: the path from an alert in the queue to an approved report. This playbook describes what the product does today, read from the code and the ADRs (008, 009, 010, 013). Items marked "not verified" could not be confirmed in the code. All data in the current build is synthetic sample data. Nothing here claims production readiness, and AISOP never performs containment.

## 1. Before you start

**Access.** You work with an API key, entered in the web app. The key is sent as `X-API-Key` (or a Bearer token) and is tied on the server to one identity and one global role. The "View as" role selector in the interface changes only what the screens show. It does not change what the server allows.

**Global roles (set on the key's identity).**

| Role | What it can do |
|---|---|
| `ingest` | Send alerts and telemetry in. Cannot read the alert queue or any case. |
| `analyst_tier_1` | Triage alerts, create cases (becomes lead of its own case), link evidence, run investigations, run the AI step. Cannot close a case or manage assignments. |
| `analyst_tier_2` | Everything Tier-1 can do, plus close or archive a case it leads, assign investigators and viewers, receive a lead transfer. |
| `security_admin` | Tier-2 capabilities, but no automatic access to any case. An admin needs a case assignment like everyone else. |

**Case roles (set per case).** `viewer` reads and cannot link evidence or run anything. `investigator` links evidence, starts investigations, runs the AI step. `lead` does all of that, records the review decision, and (if Tier-2 or admin) closes the case.

**Rules that follow from this**
- A case you are not assigned to looks like it does not exist (HTTP 404). That is by design.
- Raw payloads are never returned by the API. You see normalized fields. Unscoped lookups of raw evidence are disabled; evidence is reached only through a case.
- Use sample data only. The Alerts page marks fixtures with a SYNTHETIC badge when the provider, host or alert id contains sample, synthetic, test or demo. Do not paste real customer data into this build.
- Ingestion is the `ingest` role's job. The Alerts page shows an "Ingest alerts" button to analyst roles, but `alerts.py` refuses an analyst-role key with HTTP 403 on ingest. Whether the button works end to end with an analyst key: not verified. For sample data, ask whoever holds the sensor (ingest) key to load it.

## 2. Triage an alert

Open Alerts. Filter by severity, category, adapter (source type), provider, host or sensor, and time. Then Inspect an alert and read, in this order:

1. **Source and provenance.** Provider, adapter, upstream alert id, observed time and ingest time (UTC), and the raw evidence SHA-256 digest. Note which sensor said this and when.
2. **What it claims versus what was observed.** The title and description are the source's statement. The extracted observables (IP, domain, hash, user, process) are the concrete artifacts you can check elsewhere.
3. **Severity.** Canonical scale: informational, low, medium, high, critical, plus unknown. It is the source's judgement mapped to one scale. It is not a measure of how well the evidence is corroborated.
4. **ATT&CK tags on the alert.** These come with the alert record. Treat them as asserted by the source. AISOP's own derived mapping appears later in the case (section 6).
5. **Case column.** "Linked (n)" means the alert is already in n cases. Check before opening a duplicate case.

**Duplicates count once.** An alert whose raw record has the same SHA-256 as one already stored is skipped at ingest, and the ingest summary reports "Duplicate Alerts Skipped". During an investigation, records with the same identity and entities within 2 seconds are collapsed into one evidence unit. Two tools reporting the same event are one piece of evidence, not two. Mirrored copies are recognized only when the sources declare a shared upstream id.

**Decide:** promote, or leave it. There is no dismiss or false-positive action on the alert itself (not verified in the UI).

## 3. Promote to a case and link evidence

1. Select Promote. A new case is created with the alert as initial evidence in one transaction (the form accepts up to 100 initial evidence ids). Title, severity and a description prefilled from the alert are editable. You become the case lead.
2. In the case workspace, open the Evidence tab and use "Link evidence" to add more normalized events by UUID. Needs investigator or lead.
3. Use the **Multi-source** tab to import `aisop.evidence/1` envelopes from other sources. Malformed records are reported and not stored. Well-formed records are preserved unchanged and de-duplicated by SHA-256.
4. Read the Evidence tab (event type, source, action, outcome, severity, observed time) and Inspect for the normalized payload. The Context and indicators tab separates observed evidence, enrichment (threat intelligence, ATT&CK reference) and AI interpretation. Keep them separate in your own notes.
5. The Activity tab is the audit trail. Every link, run, review and export appears there with the actor.

Limits: at most 1,000 evidence rows per investigation run. A closed or archived case accepts no new investigation.

## 4. Run the deterministic investigation and read the verdict

In the **Multi-source** tab select "Start multi-source investigation". It needs investigator or lead. It uses no language model, only evidence linked to this case, and returns a timeline, correlation, ATT&CK mapping, a sufficiency verdict and a report. Running it again on identical evidence returns the stored result. "Force a new run" appends a new audit record.

If a red notice says the evidence changed after the run, the result is stale. Run it again.

The **verdict banner** shows SUFFICIENT, LIMITED or INSUFFICIENT with the rule version (suff-v4 after ADR-013), reason codes in plain words, and "What would raise this verdict". "Why this result?" lists the evidence units, collapsed duplicates, pairs examined and exclusions.

| Verdict | Meaning | What you do |
|---|---|---|
| SUFFICIENT | At least one different, attested record is joined to the question by a strong or specific link (logon session, process GUID, file hash, domain, public IP, URL, e-mail). Limitations still apply. It is not a confirmed finding. | Review the timeline and mapping, then proceed to report and decision. |
| LIMITED | Bounded findings only. Not confirmed conclusions. | Read every reason code. Gather what each code asks for, or state the limits in the report. |
| INSUFFICIENT | No usable evidence for the question. No AI analysis runs and no conclusion is offered. The deterministic report is still produced. | Fix the evidence gap (below) or record that the question cannot be answered yet. |

**Reason codes and the response**

| Code | Verdict effect | Response |
|---|---|---|
| `NO_EVIDENCE` | Insufficient | Link evidence to the case. |
| `NO_RELEVANT_EVIDENCE` | Insufficient | Link records that relate to the question. |
| `GATE_EVALUATION_ERROR` | Insufficient | The check failed internally. Run again; if it repeats, report it. |
| `UNCORROBORATED_QUESTION` | Limited | Only one independent source supports the question. Add a second, independent source that shares a specific artifact (file hash, public IP, domain, logon session). |
| `CONTRADICTORY_EVIDENCE:<kind>` | Limited | Records disagree and the conflict is unresolved. Find a record that settles which is right. Kinds implemented: ordering, outcome, identity, temporal. |
| `ROOT_ABSENT` | Limited | Link the record that started the activity, such as the first alert or process creation. |
| `ROOT_PROVENANCE_MISSING`, `PROVENANCE_UNVERIFIED_ALL` | Limited | Records lack a stored raw digest. Re-ingest through normal intake. |
| `TEMPORAL_ANOMALY` | Limited | Event times fall outside the window or in the future. Check them. |
| `EVIDENCE_TRUNCATED` | Limited | Too much linked evidence. Narrow what is linked. |
| `MISSING_REQUIRED_FIELD:<type>` | Limited | Fix the field in the source record and ingest again. |

Disclosure-only codes do not lower the verdict but you must read them: `PROVENANCE_PARTIAL`, `DUPLICATE_EVIDENCE_COLLAPSED`, `IRRELEVANT_EVIDENCE_EXCLUDED`, `WEAK_LINK_ONLY` (related only by host, user, internal IP or process name, which never corroborates), `REPEATED_OBSERVATION_ONLY` (same sensor repeating itself, which never corroborates).

Also read the **Data-quality problems** box: rejected records (with a plain-language reason and SHA-256 prefix) and contradictions. A record with no usable timestamp is kept as evidence but not placed on the timeline, because AISOP never invents a time.

## 5. The optional AI investigation

The deterministic result is complete without AI. Start the AI step only when you want a plain-language explanation of what the evidence already supports.

- **When.** After a deterministic run exists, and ideally when the verdict is SUFFICIENT or LIMITED. If the verdict is INSUFFICIENT the platform abstains and does not call the model.
- **How.** In the Multi-source tab choose "Run AI explanation" (investigator or lead). It runs a local model, can be slow, times out in the browser after 90 seconds, and can be cancelled. The deterministic result does not change. Per run, at most 5 incidents get a model call. The case header also has "Start AI investigation", which runs the older case synthesis and shows its output in the Findings tab. Both are human-initiated and neither runs automatically.
- **Status line per incident.** `abstained` (evidence insufficient), `disabled` (AI off by configuration, deterministic fallback shown), `fallback:<reason>` (provider failure or invalid output, deterministic fallback shown), `skipped:` (per-run limit reached), or a guardrail decision for a completed run.

**Reading claims.** Every claim carries a category and a grounding status.

| Label you see | Meaning |
|---|---|
| Observed fact (AI-stated) / "Cited and text-screened (legacy grounding)" | The cited events exist and a text screen passed. It is the model's statement of a fact. It is not analyst confirmation and not a check of the whole sentence. |
| Inference (analyst review required) | The model's reasoning beyond what is directly observed. A LIMITED verdict demotes inferences resting on fewer than two independent evidence units. |
| Unsupported (indeterminate) | The cited evidence does not back the claim. It is shown, not hidden, so you can see what the model said and that nothing supports it. Do not use it. |
| Contradicted by evidence | The cited evidence disagrees with the claim. |

Under each claim a separate **Verification** line says whether its listed assertions were supported, contradicted, had insufficient evidence, or are not machine-checkable. It checks only those listed assertions. Confidence is reported by the model and is not a measure of evidence strength. An AI conclusion is never observed evidence and never counts as corroboration. Only you can confirm a claim.

## 6. ATT&CK mapping

The Multi-source ATT&CK table lists techniques derived by explicit, versioned rules (`attack-map-v1`, six rules per ADR-009; current rule count not verified). Each row shows the technique, tactics, the rule id, the independent evidence count, whether a source also asserted it, and the rule's limitation. Techniques a source asserted that no rule derived appear separately as "asserted but NOT derived (unverified)". They are not mappings.

**To challenge a mapping**
1. Open the rule row and read its limitation.
2. Find the evidence behind it in the timeline (same incident) and check it with your own eyes: right host, right order, right outcome.
3. Check the independent evidence count. 1 means a single source.
4. Check for contradictions. A file older than the e-mail that supposedly delivered it blocks the delivery technique when a verified causal link shows the reversal.
5. If you disagree, the lead rejects the result with a note (section 8) and the report must state the technique as not accepted. There is no per-technique dispute control in the UI (not verified elsewhere).

Never add a technique to a report because it "fits". Only evidence-backed rules map.

## 7. Decision points

AISOP records decisions and recommendations. It does not isolate hosts, kill processes, disable accounts or deploy rules. The incident owner acts outside AISOP.

| Decision | Who may do it | How |
|---|---|---|
| Close or archive | Case lead holding Tier-2 or security_admin. A Tier-1 lead cannot. | "Close case" with a mandatory reason (5 to 1,000 characters). Terminal: no further investigation. |
| Escalate | Current case lead. | Transfer lead to a Tier-2 or admin analyst, with a mandatory reason. The outgoing lead becomes investigator. Tier-1 may not receive leadership. Whether the target must already be assigned: not verified. Tier-2 or admin leads can also assign more investigators. |
| Request more telemetry | Any investigator or lead as an analyst action. | There is no ticketing or request workflow in AISOP. Name the missing source in the review note (500 characters) and your own hand-off, using the "What would raise this verdict" list. Keep the case open. |
| Approve or reject the result | Case lead (API). The interface shows the controls for Tier-2 and admin views only. | Section 8. |

Close only when the question is answered, or when you record in the closure reason why it cannot be. Do not close a LIMITED or INSUFFICIENT case as "resolved" without saying so.

## 8. Produce and approve the report

Human approval is required. Nothing is released automatically.

1. The deterministic report per incident is in the Multi-source tab under "Investigation report". It prints the sufficiency verdict in the body.
2. The **case lead** reads the current result and selects "Approve this result" or "Reject this result", with an optional note. The decision is bound to the evidence fingerprint the lead saw and is written to the audit trail.
3. After approval, "Download approved report (.md)" releases the report. The server refuses (HTTP 409) if the lead has not approved the current result or the evidence changed since. The export is audit-logged with the approver.
4. If the evidence changes, the approval turns stale. Re-run, review again, then export.
5. A review records a human decision. It does not change the investigation or the evidence.

The Reports page and "Report bundle" synthesize an executive, technical and detection view and can export JSON or Markdown. In the code read, that export has no lead-approval step. Treat it as a draft for your own use and do not send it outward. Detection suggestions are leads for an engineer, not deployable rules. A case with an unresolved material contradiction is not a validated basis for a detection rule (ADR-013).

## 9. Evidence handling and chain of custody

- The raw record and its SHA-256 are stored at ingest. Duplicates are matched by that hash. The timeline shows each event's raw SHA-256 prefix.
- Never edit evidence. No API in the code read edits or deletes it. If a record is wrong, ingest a corrected record as new evidence and note why. An altered copy has a different hash, so it is a different record.
- Never invent a timestamp, source, relationship or confidence. If something is missing, say it is missing.
- Treat all evidence text as untrusted. Do not execute, open or paste commands from it into a live system.
- Case access is scoped. Raw payloads are not returned, and viewers see sanitized summaries only.
- The audit trail (Activity tab) is append-only, enforced by database triggers on PostgreSQL. That behavior on a live database: not verified in this build. Raw-evidence immutability at the database level: not verified.
- The investigation's hash-chained ledger shows "verified" or "NOT verified". It is tamper-evident, not immutable.
- A SHA-256 proves the record is unchanged since ingestion. It does not prove the source told the truth.

Keep in your notes: case number, evidence UUIDs, SHA-256 prefixes, the verdict with its rule version, and who approved what and when.

## 10. One-page checklist

1. Right key and role for the task. Sample data only.
2. Read the alert: source, time, observables, severity, digest. Check the Case column.
3. Promote. Link all related evidence. Import other sources.
4. Start the multi-source investigation. Note the verdict and every reason code.
5. Read data-quality problems, contradictions and rejected records.
6. Act on each reason code: add evidence, resolve conflict, or state the limit.
7. Check ATT&CK rows against the evidence. Ignore asserted-only techniques.
8. Optionally run the AI explanation. Treat claims as unconfirmed. Discard unsupported ones.
9. Record decisions: close, escalate, or request telemetry, with reasons.
10. Lead reviews the current result. Export only after approval.
11. Confirm no evidence was edited and the result is not stale.

## Common situations

| Situation | What AISOP shows | Correct response |
|---|---|---|
| Single uncorroborated alert | LIMITED with `UNCORROBORATED_QUESTION`. | Do not call it confirmed. Look for a second independent source sharing a file hash, public IP, domain or logon session. If none exists, report it as unconfirmed and request that telemetry. |
| Duplicate alerts | Skipped at ingest or collapsed with `DUPLICATE_EVIDENCE_COLLAPSED`. | Count it once. Do not cite duplicates as corroboration. Only a distinct source counts. |
| Same sensor repeating | `REPEATED_OBSERVATION_ONLY`. | Not corroboration. Find a different kind of observation. |
| Contradicting records | LIMITED with `CONTRADICTORY_EVIDENCE:<kind>`, contradictions listed. | Do not pick a side silently. Find the record that explains it, or state the conflict in the report. Do not close as resolved. |
| Threat intelligence only | Shown as enrichment, never as observed evidence. | Context only. An intel hit on an address does not prove an event happened. Look for the observed activity. |
| Analyst statement only | Shown as a separate class. | Not technical corroboration. Back it with observed records. |
| Missing or invalid timestamp | Rejected from the timeline with `TIMESTAMP_MISSING_OR_INVALID`. Kept as evidence. | Do not supply a time. Fix it at the source and re-ingest, or note the gap. |
| Related only by host or user | `WEAK_LINK_ONLY`, context membership. | Not corroboration. Look for a shared specific artifact. |
| Model disabled or failed | `disabled` or `fallback:<reason>`, deterministic fallback shown. | Carry on with the deterministic result. It is complete without AI. Do not treat the fallback as AI output. |
| Evidence changed after the run | Stale notice, approval stale. | Re-run, review again, then export. |
| Export refused (409) | "Lead has not approved the current result". | Ask the case lead to review the current result. |
| Tier-1 wants to close | Close is not available to a Tier-1 lead. | Escalate: transfer lead to a Tier-2 or admin analyst with a reason. |

## Not verified and known limits

- Behavior on PostgreSQL, with a live model, and under browser testing: not verified in this guide.
- The ADRs for the gate, correlation and case integration (008, 009, 010) are PROPOSED. ADR-013 is approved and PARTIAL (the STATE contradiction kind is not implemented).
- Only synthetic, author-built samples are tested. Behavior on real vendor exports is not verified.
- Whether the Alerts page "Ingest alerts" works with an analyst key, and whether a lead-transfer target must already be assigned: not verified.
- A dedicated dismiss action for alerts, a per-technique dispute control and a telemetry-request workflow were not found.
- `docs/12_User_Guides/User_Guide.md` and `Admin_Guide.md` were empty when this playbook was written, so setup and key issuance are not covered here.
