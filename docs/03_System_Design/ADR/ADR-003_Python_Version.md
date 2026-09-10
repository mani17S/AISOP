# ADR-003: Python Version Selection

| Field | Value |
|-------|-------|
| **ID** | ADR-003 |
| **Status** | APPROVED |
| **Date Proposed** | 2026-09-09 |
| **Date Approved** | 2026-09-09 |
| **Decision Maker** | Project Owner |

---

## Question

Which Python version should AISOP standardize on for development, and how
should the broken virtual environment be restored?

## Context

The development environment is currently broken. The existing
`.venv/pyvenv.cfg` references `C:\Python314\python.exe`, which does not exist
on the developer's machine. The actual Python 3.14 installation is at
`C:\Users\sarik\AppData\Local\Python\pythoncore-3.14-64\python.exe`.

This means:

- `pytest` cannot run (confirmed: *"did not find executable"*).
- No backend code can be executed or validated.
- No new dependencies can be installed.
- The development feedback loop is completely blocked.

The existing `requirements.txt` was frozen against Python 3.14 (`.pyc` files
in the repo contain `cpython-314` markers).

Available Python versions on the development machine:

- Python 3.14.6 (default via `py` launcher)
- Python 3.13 (64-bit)
- Python 3.12 (64-bit)
- CPython 3.11.15 (Astral/uv managed)

AISOP Master Prompt references:

- §4: *"Reproducible setup, clear documentation, easy extension by
  contributors."*
- §27: *"The eventual repository should be understandable to an external
  contributor."*

## Options Considered

### Option A: Re-Initialize `.venv` with Python 3.14

Delete the existing `.venv` and create a fresh virtual environment using
Python 3.14. The existing `requirements.txt` was frozen against 3.14, so all
138 pinned packages should install without conflicts.

### Option B: Patch `pyvenv.cfg` In-Place

Edit `.venv/pyvenv.cfg` to point to the correct Python 3.14 path. Attempt to
salvage existing installed site-packages.

### Option C: Re-Initialize `.venv` with Python 3.12

Create the virtual environment using Python 3.12, a more stable and widely
deployed version. The `requirements.txt` may need minor version adjustments
for packages that don't publish wheels at the exact pinned versions for 3.12.

## Trade-Off Analysis

| Criterion | Option A: Reinit 3.14 | Option B: Patch | Option C: Reinit 3.12 |
|-----------|----------------------|-----------------|----------------------|
| Local-First Deployment | Strong | Weak | Strong |
| Open-Source Extensibility | Adequate | Weak | Strong |
| Security | Strong | Weak | Strong |
| Maintainability | Adequate | Weak | Strong |
| Developer Experience | Adequate | Weak | Strong |
| Testing | Strong | Weak | Adequate |
| Operational Complexity | Strong | Weak | Strong |

Key trade-off: Python 3.14 matches the existing frozen `requirements.txt`
(fastest setup) but 3.12 has the widest ecosystem wheel availability, longest
remaining support window, and best contributor accessibility.

## Recommendation

Option A (Python 3.14) was recommended for immediate development velocity.
Option C (Python 3.12) was recommended for long-term contributor
accessibility. Both are valid; the choice depends on whether contributor
reach or setup speed is prioritized.

## Decision (Project Owner — 2026-09-09)

**APPROVED: Python 3.12 (Option C).**

The existing broken `.venv` should eventually be recreated using Python 3.12.

Rationale: Prioritize contributor compatibility and ecosystem stability.

The environment shall not be recreated or dependencies installed until that
becomes part of an explicitly approved Phase 0 implementation task.

## Architectural Consequences

1. The existing `.venv` directory will be deleted and recreated with Python
   3.12 during an approved Phase 0 task.
2. `requirements.txt` will likely need adjustments:
   - Some packages may not have wheels for the exact pinned versions on
     Python 3.12 (especially `torch`, `transformers`, `sentence-transformers`
     which are pinned to very recent versions that may target 3.13+/3.14).
   - Several LangChain packages will be removed entirely per ADR-001.
   - `chromadb` and its dependencies will be removed per ADR-002.
   - The resulting `requirements.txt` will be substantially leaner.
3. A `python_requires = ">=3.12"` constraint should be added to a future
   `pyproject.toml`.
4. CI/CD (GitHub Actions, if configured) should test against Python 3.12.
5. Contributors on any platform with Python 3.12+ can set up the development
   environment.

## Risks

1. **Risk (Medium): Dependency Version Conflicts.** The current
   `requirements.txt` was frozen on Python 3.14. Some exact-pinned package
   versions may not have pre-built wheels for Python 3.12. **Mitigation:**
   During Phase 0, regenerate `requirements.txt` from a curated list of
   direct dependencies (not the full freeze), then resolve to compatible
   versions on 3.12.
2. **Risk (Low): Python 3.14-Specific Syntax.** If any existing code uses
   Python 3.14-specific syntax features, it will fail on 3.12.
   **Mitigation:** The only functional code (`config.py`) uses standard
   Python 3.10+ syntax. No 3.14-specific features detected.
