"""
Start the AISOP backend on Windows or Linux.

psycopg's async mode cannot use the default Windows ProactorEventLoop, which makes every database call fail with
"Psycopg cannot use the 'ProactorEventLoop'". This launcher selects the selector loop before uvicorn starts and then
serves the application. Run it from the repository root:

    .venv\\Scripts\\python.exe backend\\run_local.py

Configuration comes from environment variables or .env (see backend/local.env.example).
"""

import asyncio
import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))
os.chdir(ROOT)  # knowledge_base/ and data/feeds/ are resolved relative to the repository root

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("AISOP_HOST", "127.0.0.1"),
        port=int(os.environ.get("AISOP_PORT", "8000")),
        loop="none",
    )
