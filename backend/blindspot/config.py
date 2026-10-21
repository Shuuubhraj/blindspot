"""Blindspot configuration: environment variables with safe defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Base directory for all runtime data (DB, workspaces, uploads). Override with
# BLINDSPOT_DATA_DIR; the individual paths below can still be overridden
# separately and take precedence.
DATA_DIR = Path(os.environ.get("BLINDSPOT_DATA_DIR", str(BASE_DIR / "data")))


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    host: str = os.environ.get("BLINDSPOT_HOST", "127.0.0.1")
    port: int = _env_int("BLINDSPOT_PORT", 8000)
    database_url: str = os.environ.get(
        "BLINDSPOT_DATABASE_URL", f"sqlite:///{DATA_DIR}/blindspot.db")
    workspace_root: Path = field(default_factory=lambda: Path(
        os.environ.get("BLINDSPOT_WORKSPACE", str(DATA_DIR / "workspaces"))))
    upload_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("BLINDSPOT_UPLOADS", str(DATA_DIR / "uploads"))))
    max_upload_mb: int = _env_int("BLINDSPOT_MAX_UPLOAD_MB", 200)
    max_extract_mb: int = _env_int("BLINDSPOT_MAX_EXTRACT_MB", 1024)
    max_extract_files: int = _env_int("BLINDSPOT_MAX_EXTRACT_FILES", 20000)
    scan_timeout_s: int = _env_int("BLINDSPOT_SCAN_TIMEOUT_S", 1800)
    tool_timeout_s: int = _env_int("BLINDSPOT_TOOL_TIMEOUT_S", 600)
    retention_days: int = _env_int("BLINDSPOT_RETENTION_DAYS", 30)
    ollama_url: str = os.environ.get("BLINDSPOT_OLLAMA_URL", "http://127.0.0.1:11434")
    ai_enabled_default: bool = os.environ.get("BLINDSPOT_AI_DEFAULT", "0") == "1"
    ai_model: str = os.environ.get("BLINDSPOT_AI_MODEL", "")
    ai_timeout_s: int = _env_int("BLINDSPOT_AI_TIMEOUT_S", 300)
    ai_max_files: int = _env_int("BLINDSPOT_AI_MAX_FILES", 12)
    ai_max_chars_per_file: int = _env_int("BLINDSPOT_AI_MAX_CHARS_PER_FILE", 4000)
    # Max tokens the model may generate per file. Lower = faster; 3000 is
    # plenty for the per-file cap of 10 findings and also kills runaway
    # "model rambles forever" generations that used to hit the timeout.
    ai_num_predict: int = _env_int("BLINDSPOT_AI_NUM_PREDICT", 3000)
    # Ollama context window. Must cover system prompt (~600 tokens) + file
    # (~1000 tokens) + generation. Ollama's default 4096 is too small and
    # silently drops the system prompt mid-generation; 8192 is safe.
    ai_num_ctx: int = _env_int("BLINDSPOT_AI_NUM_CTX", 8192)
    # Snippet-targeted review: instead of whole files, the reviewer gets
    # merged windows around priority-pattern hits (see ai/review.py).
    # Far fewer tokens per call, sharper focus on risky code.
    ai_snippet_mode: bool = os.environ.get("BLINDSPOT_AI_SNIPPET_MODE", "1") == "1"
    ai_snippet_radius: int = _env_int("BLINDSPOT_AI_SNIPPET_RADIUS", 35)
    ai_max_snippets: int = _env_int("BLINDSPOT_AI_MAX_SNIPPETS", 24)
    # Timeout for on-demand per-finding AI verify/fix calls.
    ai_ondemand_timeout_s: int = _env_int("BLINDSPOT_AI_ONDEMAND_TIMEOUT_S", 180)
    api_token: str = os.environ.get("BLINDSPOT_API_TOKEN", "")  # optional; "" = no auth on localhost

    def ensure_dirs(self) -> None:
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        Path(self.database_url.replace("sqlite:///", "")).parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
