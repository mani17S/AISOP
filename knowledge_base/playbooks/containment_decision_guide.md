# Containment decision guide

## Who acts
AISOP never performs containment. It does not isolate hosts, kill processes, disable accounts, block addresses or deploy detection rules. The analyst records a recommendation in the case, and the incident owner carries out the action in their own tools. Detection rules need human approval and are never deployed automatically.

## Match the recommendation to the evidence
- SUFFICIENT verdict with independent corroboration: a containment recommendation is reasonable. State which records support it.
- LIMITED verdict: recommend only reversible, low-impact steps, such as closer monitoring, a credential review or collecting more telemetry. State the reason codes next to the recommendation.
- INSUFFICIENT verdict: do not recommend containment on this evidence. Recommend collecting the missing evidence.
- Unresolved contradiction between records: resolve it first, or recommend containment only with the conflict disclosed.

## Evidence that never justifies containment alone
- A single uncorroborated alert.
- Duplicate or repeated copies of one observation.
- Threat intelligence about an address or hash. It is context and does not prove that an event happened.
- An analyst statement or an AI conclusion with no observed record behind it.
- Records related only by host, user or internal address.

## Weigh impact
- Consider the asset's role, the user, business impact and whether the step can be undone.
- Prefer the least disruptive step that stops the observed behaviour.
- If time is critical and the evidence is thin, say so plainly and let the incident owner decide.

## Record the decision
- Put the recommendation, the verdict and rule version, the supporting evidence IDs and any limits in the case review note or closure reason.
- Escalation means the case lead transfers leadership to a Tier-2 or admin analyst, with a reason. A Tier-1 lead cannot close a case.
- Closing needs a Tier-2 or admin lead and a mandatory reason. Closing does not mean containment happened.
- After the incident owner acts, add the outcome as new evidence rather than editing earlier records.
