# Sources and acknowledgements

What AISOP uses from other people, how, and what is not used. Written 2026-11-23 from the project's reference register (`D:\AISOP-Control\AISOP_REFERENCE_REGISTER.md`), the reference use log, and the dependency lists in the repository. A reference in the register is a remembered source, never an approved dependency.

Colour key for the "In the product?" column: **Code** runs in AISOP; **Data** is read by AISOP at run time; **Guidance** shaped decisions but no text or code was taken; **No** is not part of the product.

## 1. Standards and data the product reads

| Source | Publisher | Use | In the product? | Licence and handling |
|---|---|---|---|---|
| MITRE ATT&CK Enterprise v20.1 (STIX 2.1, tag `v20.1`) | The MITRE Corporation | Validates technique identifiers, names and tactics for evidence-backed mappings | Data, read from a local path, not copied into the repository | MITRE ATT&CK terms of use; file pinned by SHA-256 in the register. Mappings come from AISOP's own rules, not from MITRE |
| MITRE D3FEND 1.6.0 (mapping and technique CSVs) | The MITRE Corporation | Defensive countermeasure suggestions shown next to ATT&CK, labelled as reference, not evidence | Data, read from a local path; hashes pinned in `backend/app/modules/defense_reference/loader.py` | D3FEND Terms of Use (copyright notice must be kept). The ATT&CK-mitigations mapping and the OWL files were not used |
| Two arXiv papers (1811.00921, 2407.18418) | their authors | Cited in `docs/10_Research/Literature_Review.md` | No | An agent summarised them from the pages. **They must be read by the project owner before being cited in the defence** |

## 2. Third-party code that runs in the product

Listed from `frontend/package.json` and `requirements.txt` (direct names only). **Licences here are as generally published and were not audited by a scanner in this project; run a licence scan before making any licence claim.**

| Part | Libraries |
|---|---|
| Backend | FastAPI, Starlette, uvicorn, Pydantic, SQLAlchemy, Alembic, psycopg, pgvector, httpx, tenacity, loguru, bcrypt, PyYAML, Jinja2 |
| Frontend | React 18, React DOM, Vite (build); fonts Geist, Newsreader and JetBrains Mono through the Fontsource packages (self-hosted, no third-party requests) |
| Tests | pytest, jsdom, esbuild |

The Newsreader font is still listed in `package.json`, but amendment A6 of the design constitution retired serif titles. Check whether it is still bundled before listing it as in use.

## 3. Video

| Source | Use | In the product? |
|---|---|---|
| Remotion 4.0.545 and React 19 (in `video/`) | Builds the demo video from real screenshots | No: separate from the application. The video file is kept out of git. Remotion has its own licence terms for companies; review them if the video is used outside the academic setting |

## 4. Design and process guidance (no code taken)

| Source | How it was used | Licence |
|---|---|---|
| Karpathy guidelines (`multica-ai/andrej-karpathy-skills`, community repository, not an official Karpathy or Anthropic product) | The working method: think first, smallest change, surgical edits, test then verify. Installed as a project skill | MIT as declared by the repository (it has no LICENSE file) |
| Unslop (`heydamir/unslop`, by Damir Sokolovsky) | Rules for removing generic AI-looking interface patterns. Applied during the redesign and the Security page. No text or code copied into the product | CC BY 4.0, attribution kept in the skill |
| UI UX Pro Max (`nextlevelbuilder/ui-ux-pro-max-skill`) | Accessibility, chart and interaction rules. Its scripts were never run | MIT |
| Impeccable (`pbakaus/impeccable`) | Critique vocabulary. Its launcher and detector were never run, because they download a binary | Apache-2.0 per the use log |

## 5. Read and assessed, not used

| Source | What happened |
|---|---|
| React Bits | Registered; consulted only for matching tasks. No component is in the product |
| 21st.dev (components, terms, privacy), Animos, MotionSites | Read and assessed by agents. Nothing copied. Animos conflicted with the project's own design rules |
| PentAGI, Shannon, public-apis, locomotion-main | Read-only for defensive ideas such as bounded tool calls and audit. Never run |
| free-for-dev | Used to find free hosting options; each provider's current terms were checked on its own site. Oracle and digitalplat refused access (403) and nic.ua's terms were not read, so those are recorded as unchecked |
| Unsloth | Registered only; not installed |
| "Motions.ai" | Could not be identified; nothing substituted |

## 6. Services used for deployment (no code from them)

Render (PostgreSQL database; the API service is not yet created), Cloudflare Pages (frontend), GitHub (source). Credentials are kept outside the repository and the staged-file scans found none in it.

## 7. Ollama and models

Run locally on the author's machine: `qwen3:4b`, `qwen2.5:1.5b` and `nomic-embed-text`. Their licences are set by their publishers and were not re-checked today. No evidence is sent to a third-party AI service in the default configuration.

## 8. How AI assistance was used

The code, tests and documents were produced with an AI coding assistant working under the author's direction, using the process in section 4. Every change was tested and committed under the author's repository. The author should be ready to explain any part of the code and to say which parts the assistant wrote.

## What this page does not claim
- That every licence above was checked by a tool: they were not.
- That the project is free of third-party obligations: attribution and the D3FEND copyright notice must be kept, and the licence scan in section 2 is still to be done.
- That the two papers have been read by a person.
