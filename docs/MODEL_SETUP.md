# Local AI review with Ollama

Blindspot's AI review is **optional, local-only, and advisory**. There is no cloud fallback anywhere in the codebase: if Ollama isn't running, the `ai_review` stage records a limitation and the scan completes normally.

## Setup

```bash
# 1. Install Ollama: https://ollama.com/download
# 2. Start the daemon
ollama serve

# 3. Pull a code-capable model (7B is a good speed/quality trade-off)
ollama pull qwen2.5-coder:7b
```

Any Ollama model works; code-focused models produce fewer hallucinations. The daemon listens on `http://127.0.0.1:11434` by default.

## Enabling it

Per scan (console toggle, API, or CLI):

```bash
blindspot scan app.apk --ai --ai-model qwen2.5-coder:7b
# API: POST /api/scans with config {"enable_ai_review": true, "ai_model": "qwen2.5-coder:7b"}
```

Environment defaults:

| Variable | Default | Purpose |
|---|---|---|
| `BLINDSPOT_OLLAMA_URL` | `http://127.0.0.1:11434` | Ollama daemon base URL |
| `BLINDSPOT_AI_DEFAULT` | `0` | set to `1` to enable AI review by default |
| `BLINDSPOT_AI_MODEL` | *(empty)* | default model when the scan doesn't name one |
| `BLINDSPOT_AI_TIMEOUT_S` | `300` | per-generation timeout |
| `BLINDSPOT_AI_MAX_FILES` | `12` | max files sent to the model |
| `BLINDSPOT_AI_MAX_CHARS_PER_FILE` | `4000` | max chars per file |

`blindspot system` (or `GET /api/system/status`) shows whether Ollama is reachable and which models are pulled.

## How the review works (`ai/`)

1. **File selection** (`review.select_review_files`): decompiled sources are scored by suspicion heuristics (crypto/network/storage/WebView keywords); the top `BLINDSPOT_AI_MAX_FILES` files are truncated to `BLINDSPOT_AI_MAX_CHARS_PER_FILE` chars. The model only ever sees bounded, real code - never the whole APK.
2. **Prompt** (`build_prompt`, version `blindspot-ai-review/1.0`): instructs the model to return findings as JSON with file path, line numbers, and rationale.
3. **Generation** (`OllamaClient.generate`): `POST /api/generate` with `"format": "json"`, `temperature: 0.1`, `num_predict: 4000` - low temperature and JSON mode to reduce free-form hallucination.
4. **Schema validation** (`validate_ai_finding`): output must parse as JSON and match the expected finding schema; malformed output is discarded, never repaired by guessing.
5. **Evidence verification**: every AI-claimed file path and line number is checked against the real workspace; claims pointing at non-existent locations are dropped.
6. **Corroboration, not promotion**: an AI suggestion within **±3 lines** of a deterministic finding on the same file is attached as `ai-corroborated`; anything else is stored as an `AIReview` row - a labeled hypothesis, visible in the report's AI section, but never a confirmed finding. Only human triage can mark a finding `confirmed`.

## Graceful degradation

- Ollama not running → `ai_review` stage notes "Ollama not available" as a scan limitation; findings from deterministic engines are unaffected.
- Requested model not pulled → stage error recorded as a limitation (the error message names the model and suggests `ollama pull <model>`); scan completes.
- Generation timeout / invalid JSON → recorded as limitations; no partial AI output is ever merged silently.
