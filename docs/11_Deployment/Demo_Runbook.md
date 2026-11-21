# AISOP Demo Runbook (local PostgreSQL deployment)

Scope: the five-day deployment show. Local machine only, synthetic data only. Status words follow the project convention: a step is described as working only where a saved log shows it.

## 1. What runs where
| Part | Address | Started by |
|---|---|---|
| PostgreSQL 17 with pgvector (container `aisop-postgres`, database `aisop_demo`) | 127.0.0.1:5433 | Docker, already running |
| Backend (FastAPI, runs as the non-superuser role `aisop_app`) | http://127.0.0.1:8010 | `scripts/demo_check.ps1 -Start` (supervisor `scripts/demo_backend.ps1`) |
| Frontend (Vite dev server, proxies `/api` to the backend) | http://127.0.0.1:3010 | `cd frontend; $env:AISOP_API_PROXY='http://127.0.0.1:8010'; npm run dev -- --port 3010` |
| Language model (optional, AI path only) | Ollama on 127.0.0.1:11434, model `qwen2.5:1.5b` | Ollama service; the deterministic path works without it |

## 2. Check that the demo is up (before every rehearsal and before the show)
```powershell
cd D:\AISOP
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\demo_check.ps1
```
It prints OK or FAIL per item and exits 1 on any FAIL: container healthy, backend health and readiness (database, pgvector), the demo analyst token accepted (status code only), the frontend answers and proxies to the backend, the supervisor is running. **Do not start a rehearsal or the show until it prints "All checks OK."**

## 3. Start or restart the backend WITHOUT `demo_up.ps1`
`demo_up.ps1` kills whatever listens on the backend port, and with `-Reset` it drops `aisop_demo` and issues new tokens (that logs everyone out and wipes the data). For a plain restart use:
```powershell
cd D:\AISOP
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\demo_check.ps1 -Stop     # stops the supervisor and the backend on :8010
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts\demo_check.ps1 -Start    # starts the supervisor detached, waits for health
```
This keeps the database and the tokens. `-Start` does nothing if the backend already answers. The supervisor restarts the backend within seconds if it exits and writes every start and exit, with the exit code, to `D:\AISOP-Backups\AISOP_Dev_Logs_20261120\supervisor_8010.log`. If that log ever shows an exit, the exit code and time are the first evidence to read.

Frontend (separate terminal, leave it open):
```powershell
cd D:\AISOP\frontend
$env:AISOP_API_PROXY = 'http://127.0.0.1:8010'
npm run dev -- --port 3010
```

## 4. Demo login
The analyst token is in `D:\AISOP-Backups\AISOP_Dev_Logs_20261120\demo_tokens_DO_NOT_COMMIT.txt` (line `analyst=...`). Copy it without displaying it:
```powershell
(Get-Content D:\AISOP-Backups\AISOP_Dev_Logs_20261120\demo_tokens_DO_NOT_COMMIT.txt | Where-Object { $_ -like 'analyst=*' }).Substring(8) | Set-Clipboard
```
Paste it on the key screen at http://127.0.0.1:3010. Use only the analyst token in the browser; the sensor token is for ingestion. The token expires seven days after issue; to reissue, run `backend/scripts/provision_demo_identities.py --rotate` against `aisop_demo` (ask before running; it invalidates the old token). Never commit the token files and keep them out of any screen recording.

## 5. Known incident: backend stopped without an error (2026-11-20, about 19:17)
The :8010 backend stopped silently. Its log ends with no shutdown line and no traceback; the Windows Application and System logs for 19:10 to 19:25 show no application crash (no python entry), no Windows Error Reporting entry for it and no resource-exhaustion event. Free memory was 2.6 of 13.9 GB, which is tight but not exhausted. **The cause was not proven.** The evidence fits an external termination of the process (for example its parent shell session ending), not a crash of the application. Counter-measures: the supervisor restarts it and records any exit code; `demo_check.ps1` is run before every rehearsal and before the show; keep memory free (close unrelated applications, stop unused models with `ollama stop`) before the show.
If the backend is found down during the show: run section 3 (about 15 seconds); say so plainly; the recorded fallback video covers the rest.

## 6. The optional AI explanation: warm-up and how to present it
Measured on this laptop (record: `D:\AISOP-Backups\AISOP_Dev_Logs_20261120\AI_LATENCY_RECORD.md`): deterministic investigation 0.6 to 0.7 s for the demo case; AI explanation about 8 s warm and 12 to 13 s when the model must be loaded (RTX 3050 4 GB, qwen2.5:1.5b). One of the two incidents falls back to the deterministic output because the small model does not return valid structured output for it.
- **Before every rehearsal and before the show:** `pwsh -NoProfile -ExecutionPolicy Bypass -File D:\AISOP\scripts\demo_check.ps1 -WarmUp`. It loads the model and keeps it for 30 minutes (the supervisor also sets a 60 s hard timeout per model call and one attempt).
- **In the app:** run the investigation first (it never waits for the model). The "AI explanation (optional)" box appears under the result. Press **Run AI explanation**; it shows the elapsed seconds and a **Cancel** button, gives up after 90 s with "AI timed out ... The deterministic result is unchanged", and a cancel or failure leaves the result as it was.
- **Say:** the investigation is deterministic and returns immediately; the AI explanation is optional, gated by the sufficiency check, claim-checked, and runs locally, so it takes seconds on this laptop. **Do not say** the AI is fast, and do not quote a timing that is not in the record.
- **If the model is slow or unavailable on the day:** skip the AI step and show the recorded AI run (plain screen recording, no tokens or key on screen).

## 7. After the show
`scripts\demo_check.ps1 -Stop`, then stop the frontend terminal. Rotate or delete the demo tokens if the machine is shared.
