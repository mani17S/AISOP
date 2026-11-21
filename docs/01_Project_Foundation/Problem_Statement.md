# Problem Statement

Status: project statement, written 2026-11-21. It describes the problem AISOP is built to address. It is not the result of a literature review (see `Research_Gap.md`).

## The problem in plain words
A security analyst investigating an incident usually has to read alerts and events from several tools and decide what they add up to. Three things make that hard and error-prone:

1. **Fragmented evidence.** The same incident appears as separate records in an endpoint tool, a network sensor, a log platform and an identity system. Linking them is manual.
2. **Repetition looks like proof.** The same record forwarded twice, or two alerts about the same underlying event, can look like two independent confirmations. That inflates confidence.
3. **Observed, inferred and generated text get mixed.** A summary, a threat-intelligence note, an analyst comment and a language-model answer can all read as fact. An assistant that invents a plausible detail is worse than no assistant.

A fourth, practical constraint: logs contain sensitive data, so sending them to a cloud language model is often not acceptable.

## What AISOP is built to do about it
AISOP is a local-first investigation workbench. It keeps each record as received (with a SHA-256), keeps the source system visible, treats duplicates and near-duplicates as one piece of evidence, never counts an analyst note, a threat-intelligence entry or a model answer as corroboration, and says "insufficient" and stops when the independent evidence does not support a conclusion. A language model is optional and its output is checked against the evidence. Everything deterministic works with the model off. The analyst makes the decisions.

## What it is not
Not a SIEM, EDR, XDR or SOAR. It does not detect, block or respond. It is a prototype evaluated on synthetic data, not a production product.

## Who it is for
A single SOC analyst or a small team, in a lab or teaching setting, working on a case at a time.

## How to tell whether it helps
By the test in `docs/10_Research/Evaluation.md`: does the independence and abstention behaviour produce fewer unsupported conclusions than naive correlation on documented scenarios? That test is defined but its results are not yet produced (see the status table there).
