"""Local settings. Paths are independent of the terminal working directory."""
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_PATH = Path(os.environ.get(
    "APP_HISTORY_DB", str(PROJECT_ROOT / "data" / "local" / "sv4.sqlite3")
)).expanduser()
