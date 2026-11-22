# Literature and Product Review

Status: first pass, written 2026-11-22. It covers 8 sources that were fetched and read for this document. It does not prove or disprove novelty. See the last section.

## Purpose

`docs/01_Project_Foundation/Research_Gap.md` states that AISOP's novelty compared with other SOC tools is unknown because no review had been done. This file is that first review. It checks the three properties the project cares about against what a small set of papers and vendor pages actually say:

1. Evidence independence: duplicates, near-duplicates and weakly related records do not count as corroboration. Analyst notes, threat intelligence and model output never count as technical corroboration.
2. Abstention: when independent evidence is insufficient, the system says so and does not call an LLM.
3. An optional LLM layer whose claims are verified against the evidence.

## How the sources were read

Each page was opened with a web fetch tool, and the summary below is limited to what the fetched text said. Where only the abstract page was available, that is stated in the entry. Product pages describe what a vendor says its product does. They are not tests of the product.

## Sources

### 1. Alert correlation (academic)

**Title:** Alert Correlation Algorithms: A Survey and Taxonomy
**Authors:** Seyed Ali Mirheidari, Sajjad Arshad, Rasool Jalili
**Year:** arXiv posting November 2018 (arXiv:1811.00921). The page says it was first presented at the Symposium on Cyberspace Safety and Security in November 2013 and published in Springer LNCS vol. 8300.
**URL:** https://arxiv.org/abs/1811.00921
**What was read:** the arXiv abstract page only. The PDF could not be read as text, so the body of the paper was not checked.
**Summary:** The paper describes alert correlation as taking alerts from different intrusion detection systems to reduce false alerts, detect higher-level attack patterns, add context to incidents, predict future attack states and find root causes. It surveys correlation algorithms suited to enterprise networks and compares each category on accuracy, functionality and computation cost. It concludes that each category has distinct strengths, so a good framework should combine them.
**Relation to AISOP:** It frames correlation as grouping and reducing alerts, and the abstract says nothing about duplicates, independence of evidence or corroboration, so AISOP's property 1 is a narrower question than the one this survey states; the body of the paper was not read, so it may say more.

### 2. Abstention in LLMs (academic)

**Title:** Know Your Limits: A Survey of Abstention in Large Language Models
**Authors:** Bingbing Wen, Jihan Yao, Shangbin Feng, Chenjun Xu, Yulia Tsvetkov, Bill Howe, Lucy Lu Wang
**Year:** first submitted 25 July 2024 (arXiv:2407.18418), latest revision 12 February 2025. The arXiv listing says it appeared in TACL; the exact year and volume were not confirmed from a page opened for this review.
**URL:** https://arxiv.org/abs/2407.18418 (full text read at https://arxiv.org/html/2407.18418v3, first 100,000 characters)
**Summary:** The survey defines abstention as the refusal to answer, from a full "I don't know" to partial abstention such as a self-contradictory answer. It organises methods and benchmarks around three views: the query, the model and human values. It lists irrelevant or insufficient context as a reason to abstain, covers calibration-based methods, and concludes that neither probability-based measures nor verbalized confidence may be well calibrated.
**Relation to AISOP:** It supports abstention on insufficient context as an established idea in general LLM work, whereas AISOP makes the abstention decision from a deterministic count of independent evidence before any model is called, which is a different trigger from model confidence.

### 3. Abstention and verification in a security task (academic)

**Title:** Hallucination-Resistant Security Planning with a Large Language Model
**Authors:** Kim Hammar, Tansu Alpcan, Emil Lupu
**Year:** 2026 (submitted 5 February 2026, arXiv:2602.05279)
**URL:** https://arxiv.org/abs/2602.05279 (details read at https://arxiv.org/html/2602.05279v1, first 100,000 characters)
**Summary:** The framework uses an LLM as decision support for incident response planning. It generates several candidate actions, measures how much the model's own predictions for them agree (a consistency score), and abstains if that score is at or below a threshold, then gathers feedback such as testing in a digital twin. It is evaluated on four public intrusion datasets covering 25 incidents with manually built ground-truth plans, and the authors list limits including a single task, theoretical assumptions and manually built labels.
**Relation to AISOP:** It is a clear example of abstention in a security setting, but the trigger is agreement among the model's own outputs, whereas AISOP's trigger is the amount of independent observed evidence, and it addresses response planning rather than evidence corroboration.

### 4. Grounded LLM analysis of security incidents (academic)

**Title:** Retrieval-Augmented LLMs for Security Incident Analysis
**Authors:** Xavier Cadet, Aditya Vikram Singh, Harsh Mamania, Edward Koh, Alex Fitts, Dirk Van Bruggen, Simona Boboila, Peter Chin, Alina Oprea
**Year:** 2026 (submitted 18 March 2026, arXiv:2603.18196)
**URL:** https://arxiv.org/html/2603.18196v1 (first 100,000 of about 125,900 characters read)
**Summary:** A library of queries mapped to MITRE ATT&CK techniques extracts indicators from raw logs, and the system retrieves the relevant chunks, tagged with their source file, to answer forensic questions. The prompt tells the model to answer from the evidence or say "Not found in provided data". The paper reports no separate verification step and no rate for how often that statement was produced. It evaluates eight LLM configurations on four malware scenarios and one Active Directory attack, and says human review is needed before acting.
**Relation to AISOP:** It grounds the model in extracted evidence and uses a prompt-level "not found" instruction, which resembles AISOP's grounding but differs in that AISOP decides to abstain before the model call and checks claims afterwards; the paper does not address duplicate evidence or weighting of independent sources, although it does link records through shared indicators such as an IP address.

### 5. Claim verification in incident reports (academic)

**Title:** DeepFaith: Evidence-Grounded LLMs for Faithful Incident Reporting in Multi-Stage APT Defense
**Authors:** Trung V. Phan, Tri Gia Nguyen, Thomas Bauschert
**Year:** 2026 (submitted 27 July 2026, arXiv:2607.24348)
**URL:** https://arxiv.org/abs/2607.24348
**What was read:** the arXiv abstract page only. The full text was not read.
**Summary:** The abstract proposes a framework that turns structured outputs of defense and explainability modules into natural-language incident reports tied to system evidence, using a unified evidence representation, evidence-grounded prompting, faithfulness-aware generation and post-generation verification. In an enterprise testbed it reports faithfulness rising from 0.68 to 0.92 and unsupported claims falling from 0.32 to 0.08.
**Relation to AISOP:** Its post-generation verification of report claims is close to AISOP's third property, and the abstract does not mention abstention or independent corroboration, though the full paper may.

### 6. Vendor: SIEM/XDR alert correlation

**Title:** Alert correlation and incident merging in the Microsoft Defender portal
**Vendor:** Microsoft (Microsoft Learn, Microsoft Defender XDR documentation)
**Year:** page metadata date 2026-11-04
**URL:** https://learn.microsoft.com/en-us/defender-xdr/alerts-incidents-correlation
**Summary:** The page says Defender aggregates alerts from all sources, adds an alert to an existing incident if it is "sufficiently related" and creates a new incident if it is "sufficiently unique" within a time frame. It says the correlation criteria are "proprietary, internal" logic, and that merges use shared entities, artifacts, time frames and multistage sequences. Merging is blocked in listed cases, such as a closed incident, different owners, different classifications or too many entities.
**Relation to AISOP:** Correlation here groups alerts into incidents by commonality, and the page does not describe counting independent sources, treating duplicates as one piece of evidence, or any confidence or sufficiency score, so it does not show property 1 as AISOP defines it; the criteria being proprietary also means nothing can be concluded about what is not documented.

### 7. Vendor: AI SOC assistant with grounding statements

**Title:** Application card - Microsoft Security Copilot
**Vendor:** Microsoft (Microsoft Learn)
**Year:** page metadata date 2026-06-22, last updated 2026-10-09
**URL:** https://learn.microsoft.com/en-us/copilot/security/security-copilot-application-card
**Summary:** The card describes a generative AI assistant for incident investigation, threat intelligence, KQL generation and reporting, and defines grounding as giving the model contextual input from connected data sources and plugins. It states that outputs can be "inaccurate, incomplete, or outdated" and may contain "unsupported conclusions", and tells users to validate critical outputs. It also says responses cite source materials, show intermediate steps in a process log, and that agents work under human oversight. Evaluations of groundedness were run with internal tools.
**Relation to AISOP:** It documents grounding, citations and human oversight, but the card puts the verification burden on the user and does not describe an automatic refusal to answer when evidence is insufficient or a claim-by-claim check against observed evidence, so it does not show properties 2 or 3 as AISOP defines them. Absence from this one card is not proof the product lacks them.

### 8. Vendor: LLM alert analysis in a SIEM

**Title:** Attack Discovery
**Vendor:** Elastic (Elastic Security documentation)
**Year:** not dated on the page
**URL:** https://www.elastic.co/docs/solutions/security/ai/attack-discovery
**Summary:** The page says Attack Discovery "uses large language models (LLMs) to analyze alerts and identify potential attacks". Each discovery groups related alerts into an attack narrative, lists the users and hosts involved, maps alerts to MITRE ATT&CK and suggests a possible threat actor. It requires at least one configured LLM connector. The fetched page does not mention accuracy measures, verification, citations, hallucination safeguards or handling of insufficient evidence.
**Relation to AISOP:** Here the LLM itself produces the grouping, the ATT&CK mapping and the actor suggestion, and this page says nothing about gating or verifying that output, which is the opposite design from AISOP, where mappings come from evidence-backed rules and the model is optional; other Elastic pages were not checked.

## Also read, not counted as citations

- Microsoft Sentinel, "Advanced multistage attack detection in Microsoft Sentinel" (https://learn.microsoft.com/en-us/azure/sentinel/fusion). It describes the Fusion machine-learning engine that combines alerts from several products into incidents, and says Fusion is disabled for workspaces onboarded to the Defender portal, where the Defender XDR correlation engine replaces it. It did not mention duplicates, corroboration or abstention.
- Ndichu, Ban, Ozawa, Takahashi, Inoue, "AI-Driven Security Alert Screening and Alert Fatigue Mitigation in Security Operations Centers: A Survey" (https://arxiv.org/abs/2605.08316), abstract page only. It reports 119 records and a four-stage taxonomy (filtering, triage, correlation, generative augmentation) and names gaps in operational validation, robustness, generalization and evaluation practice. A reader who wants a broader recent map of SOC alert work should read its full text.

## Unverified

These were seen in search results or in my own background knowledge but not opened and read, so they are not cited above and should not be repeated as support until someone reads them:

- Hammar, Alpcan and Lupu's NDSS 2026 paper on a lightweight LLM with retrieval for incident response (appeared in search results only).
- The Elastic blog "Behind the scenes of Elastic Security's generative AI features" and other Elastic Security AI Assistant pages.
- Microsoft Security Copilot responsible AI FAQ pages beyond the application card above. A fetch of the FAQ URL returned the application card instead.
- Any Splunk, CrowdStrike (Charlotte AI), Google, Palo Alto or open-source SOC assistant documentation. None was opened in this pass, so nothing is claimed about them.
- The full text of Mirheidari et al. (PDF would not parse), and the full text of DeepFaith. Whether either discusses duplicate alerts, independence or abstention is unknown.
- The exact TACL year and volume of the abstention survey. The arXiv listing says TACL, and a search result URL pointed to an ACL Anthology record numbered 2025.tacl-1.26, but that record was not opened.
- Whether any product's proprietary correlation logic discounts duplicates or near-duplicates internally. The Defender page says its criteria are not published.

## What this review does and does not show

**What the sources say, in plain terms.**

- Property 1, evidence independence. None of the eight pages describes a rule that duplicates and near-duplicates count as one piece of evidence, or that analyst notes, threat intelligence and model output are barred from counting as technical corroboration. The correlation sources (1 and 6) describe grouping alerts by shared entities, artifacts, time or sequence. Source 4 links records through shared indicators. This is a statement about the pages read. Two of them (1 and 5) were read only at abstract level, and Microsoft says its correlation criteria are proprietary.
- Property 2, abstention. Abstention itself is clearly established in general LLM research (source 2). In security work it appears in sources 3 and 4, but triggered by model self-consistency (3) or by a prompt instruction to the model (4). None of the pages read describes refusing to call a model because the count of independent observed evidence is too low.
- Property 3, claim verification. Source 5 describes post-generation verification of report claims against evidence, so this property is addressed elsewhere at least in that form. Sources 4, 7 and 8 describe grounding, citation or human review but, in the pages read, not an automatic claim-level check.

**Limits.**

- A review of 8 sources cannot prove novelty. Not finding a feature in a small set of pages is different from the feature not existing. Splunk, CrowdStrike, Google and open-source SOC assistants were not covered, and there may be papers on evidence weighting, multi-sensor fusion or fact verification that were not searched for.
- Vendor documentation describes marketed behaviour and was not tested. Proprietary logic may do more than the pages say.
- The honest reading is limited. Claim verification looks addressed elsewhere. Abstention is addressed elsewhere in other forms and with other triggers. Independence as AISOP defines it was not found in the pages read, and the supportable wording is "not found in this limited review", not "absent from the field".
- Any novelty claim for the panel would need a wider search (for example, on source independence in evidence combination and on retrieval-augmented abstention), and the evaluation in `docs/10_Research/Evaluation.md` to show the properties help in practice.
