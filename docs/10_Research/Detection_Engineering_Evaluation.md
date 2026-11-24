# Detection engineering evaluation: ATT&CK rules against public attack captures with someone else's labels

Started 2026-11-24. This document is written in two steps on purpose: the protocol, the development result and the **freeze** are committed first; the held-out result is added only after the held-out data has been run once.

## Why this exists
The earlier ATT&CK score (`backend/evaluation_tools/score_attack_mapping.py`) used 20 scenarios and six rules written by the same person, so it could only show consistency. A reviewer's fair question is whether the rules find anything in telemetry nobody on this project wrote.

## Truth and its limits
- **Data:** the OTRF Security-Datasets (`github.com/OTRF/Security-Datasets`, MIT licence), Windows host captures of simulated attacks (Sysmon, Windows Security, PowerShell logs). Raw captures are kept outside the repository (`D:\AISOP-Reference-Data`).
- **Labels:** each dataset's metadata lists the ATT&CK technique(s) its author says the simulation demonstrates. The labels were written by the dataset authors, not by this project.
- **What a label means:** a dataset-level statement "this capture demonstrates technique T", not an event-level label. A capture also contains other real activity the author did not label, and the author's label is sometimes loose (for example one dataset labelled T1003.003 contains a Kerberos ticket tool).
- **Not measured here:** precision against labelled benign data (none used), behaviour on real incidents, or any claim about unseen attack tools. "Other techniques emitted" is reported, not counted as false positives automatically.

## Protocol (fixed before any rule was written or any result seen)
1. All 98 Windows datasets with a documented technique and a host archive are split into **dev** and **held-out** by the SHA-256 of the dataset id (first byte even = dev). The split depends on nothing but the id (53 dev, 45 held-out).
2. Rules are developed on **dev** only. The held-out archives were not downloaded until the freeze below was committed.
3. Datasets the host cannot open (six Empire-based dev captures were blocked with a permission error, probably endpoint protection reacting to attack-tool text; no security setting was changed) and archives over 6 MB are excluded identically on both sides and counted.
4. After the freeze the held-out side is run **once**. If a rule is changed afterwards, that side is no longer held out and the report says so.
5. Scoring: a documented technique counts as recovered at **parent level** if any rule emitted that technique or a sibling with the same parent (the convention of the existing scorer), and as **exact** if the identical id was emitted. Both are reported; exact is the stricter number.

## Baseline before any change (dev side)
The existing six rules (`attack-map-v1`) recovered **0 of 50** documented techniques (46 readable datasets, 333,038 records; 308,746 accepted by the normaliser).

## What was built
- `endpoint-attack-v1` (`backend/app/modules/correlation/mitre_endpoint.py`): 39 rules over process command lines and typed Sysmon / Windows Security fields, written from the public definition of each technique, not from tool names. Each carries a limitation statement.
- A bounded view of source-supplied typed fields on the event (`source_fields`: a fixed whitelist, 300 characters, copied verbatim, never an entity or a link).
- The table runs in the live workflow next to the other two tables, and its version is recorded in the audit trail and the result.
- 44 tests: each rule has a canonical positive and a benign look-alike that must not fire.

## Development result (dev side, rules as frozen below)
| | Result |
|---|---|
| Datasets scored | 46 of 52 (6 unreadable) |
| Documented techniques | 49 |
| Recovered at parent level | **24** (49%) |
| Recovered exactly | **22** (45%) |
| Datasets with at least one recovery | 24 of 46 |

This is **not** an unbiased number: I looked at the command lines in these captures while writing rules, and one rule bug (a hive export mistaken for a hive save) was found and fixed from dev output. The held-out number is the one to quote.

Misses on dev, and why (none were fixed by adding a rule for the specific tool):
- Telemetry not in the capture: a UAC-bypass registry change appears only in PowerShell pipeline logs, and the EventLog-disable registry events do not exist in two captures. PowerShell logging is not a source the rules read.
- Techniques whose evidence is lateral-movement or Kerberos activity the rules do not model (DCOM, remote service creation, DCSync, ticket requests).
- Loose or tool-named labels (generic T1059, T1012 for a discovery tool run, T1112).

Emitted outside the documented technique (reported honestly, not all false positives):
- `T1070.001` in about 20 captures: Windows Security event 1102 (audit log cleared), a real event the lab operator caused when resetting the machine. Correct by the rule's definition, irrelevant to the labelled technique.
- `T1003.001` once from an Azure guest agent reading LSASS with the read-memory right: an environmental false positive, not tuned away.
- `T1055` twice from real remote-thread events (one from `WmiPrvSE` into `notepad`, one from `iexplore` into an unknown process).
- `T1012` and `T1003.002` (before the hive fix) from real `reg query` and `reg export` commands.

## Freeze (committed before the held-out data was downloaded)
| File | SHA-256 |
|---|---|
| `backend/app/modules/correlation/mitre_endpoint.py` | `ad7fbd6b97968cbd8245f3db7ed5daddfc92dbebb95668287ce17933733b9ef0` |
| `backend/app/modules/correlation/mitre.py` | `a411d63404b5d0dace5a60f7e69507a03d8cf090f6fc76905f91f755f6f4c9bb` |
| `backend/app/modules/correlation/normalize.py` | `91914e4bc997fc3c8481e3c292bade5f50217bf531df8ec3896b51b01647e65f` |

Held-out run command: `.venv\Scripts\python.exe backend\evaluation_tools\score_attack_datasets.py --side heldout --out <file>`. If the three hashes above do not match the files used for the held-out run, the run does not count.

## Held-out result (run after the freeze; the three hashes above were re-verified unchanged immediately before the run)
One earlier attempt scored zero datasets because the downloader crashed on a file the host blocked; no rule was evaluated and nothing was seen, so no information leaked. The downloader was then made to count blocked files as unreadable, as on the dev side, and the held-out side was run.

| | Dev (inspected while developing) | **Held-out (not seen)** |
|---|---|---|
| Datasets scored | 46 of 52 | **34 of 44** (10 unreadable or empty) |
| Documented techniques | 49 | **34** |
| Recovered, parent level | 24 (49%) | **11 (32%)** |
| Recovered, exact | 22 (45%) | **9 (26%)** |
| Old six rules alone, parent level | 0 | **1 (3%)** |
| New endpoint table alone, parent level | 24 | **10 (29%)** |
| Wilson 95% interval on parent-level recovery | about 35% to 63% | **about 19% to 49%** |

Reading it honestly:
- **The gain is real and comes from the new table.** On data nobody on this project wrote or labelled, the original six rules found 1 of 34 documented techniques; the combined tables found 11.
- **It is not a good detector.** Two of three documented techniques were not recovered. The number to quote is about one in three, with an interval from about one in five to one in two. 34 techniques is a small sample.
- **Dev was optimistic by about 17 points** (49% against 32%), as expected from inspecting dev while writing rules. The two intervals overlap, so the size of the drop is not proven, only its direction.
- **Recovery is parent level for the headline** (the existing scorer's convention). Exact recovery is lower (26%) because, for example, a rule for LSASS memory also covers a sibling credential-dumping label.

Held-out misses by documented technique family (none were addressed afterwards, so the held-out side stays clean): lateral movement over SMB, DCOM and remote services (5), credential dumping variants (3), defence-evasion events not present in the capture (3), generic or loosely-labelled proxy execution (2), and single cases of token abuse, DLL hijacking, microphone capture, group discovery, remote-service exploitation, a web shell, injection and scheduled tasks.

What the rules emitted outside the documented technique (held-out, 28 of 39 emitted pairs): 11 are `T1070.001` from Windows Security event 1102 (the lab clearing its logs; correct by the rule's definition); 12 come from the six original rules (`T1071`, `T1027`, `T1059.001`); the 8 that remain from the endpoint table are `T1055` (3), `T1003.001` (2) and one each of `T1547.001`, `T1136.001` and `T1021.002`. Whether each is a false positive was not adjudicated; capture authors label only the activity they meant to demonstrate.

## What this does and does not establish
- It establishes that, on third-party captures, the shipped rules now find roughly a third of the documented techniques where they found almost none, with the evidence behind each hit being a specific command line or typed event that can be shown to the analyst.
- It does not establish precision, behaviour on real incidents, or coverage of tools and techniques outside these captures. There is still no benign background corpus here, so a false-positive **rate** is not available.
- Any rule change after this point uses a fresh held-out set; reusing this one would no longer be held out.
