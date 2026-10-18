"""Ollama client: local-only LLM inference.

No cloud fallback exists anywhere in Blindspot. If Ollama is not running,
callers must degrade gracefully and say so.
"""

from __future__ import annotations

import httpx

from ..config import settings

PROMPT_VERSION = "blindspot-ai-review/1.0"


class OllamaClient:
    def __init__(self, base_url: str = "http://127.0.0.1:11434",
                 timeout_s: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s

    def is_available(self) -> bool:
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=self.timeout_s)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> list[str]:
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=self.timeout_s)
            r.raise_for_status()
            return [m.get("name", "") for m in r.json().get("models", [])]
        except Exception:
            return []

    def generate(self, model: str, prompt: str, timeout_s: int = 300,
                 num_predict: int | None = None) -> str:
        """Non-streaming generation. Returns raw text. Raises on failure."""
        r = httpx.post(
            f"{self.base_url}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False,
                  "format": "json",
                  "options": {"temperature": 0.1,
                              "num_ctx": settings.ai_num_ctx,
                              "num_predict": num_predict
                              if num_predict is not None
                              else settings.ai_num_predict}},
            timeout=timeout_s,
        )
        r.raise_for_status()
        return r.json().get("response", "")
