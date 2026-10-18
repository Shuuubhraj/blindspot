# Blindspot security model

Blindspot analyzes potentially hostile APKs. This document describes the guarantees the platform makes - and the ones it deliberately does not.

## Local-first guarantees

- **No data leaves the machine.** Analysis, AI review (Ollama), and report rendering all run locally. There is no telemetry, no cloud API, no metrics upload.
- **Localhost by default.** The API binds `127.0.0.1:8000` unless `BLINDSPOT_HOST` is changed. The console is served from the same origin; the HTML report is fully self-contained (no external CSS/JS/fonts).
- **Optional API token.** Setting `BLINDSPOT_API_TOKEN` requires an `X-API-Token` header on every `/api/*` endpoint except `/api/health`. Empty (default) = no auth, intended for single-user localhost use.

## Handling untrusted APKs

- **Upload validation** (`analysis/apk.py`): magic bytes (`PK\x03\x04`), ZIP structural integrity check, SHA-256 computed at upload, streaming write with an early size guard (`BLINDSPOT_MAX_UPLOAD_MB`, default 200). Invalid files are rejected with 422 and deleted; oversized uploads with 413.
- **Extraction hardening**: per-scan isolated workspace, symlink entries skipped, entries resolving outside the workspace rejected (zip-slip), caps on extracted bytes (`BLINDSPOT_MAX_EXTRACT_MB`, default 1024) and file count (`BLINDSPOT_MAX_EXTRACT_FILES`, default 20000).
- **Tool sandboxing**: third-party tools (jadx, apktool, mobsfscan) run as subprocesses with timeouts (`BLINDSPOT_TOOL_TIMEOUT_S`, default 600) and output captured to the scan workspace, never executed code from the APK.
- **Workspace lifecycle**: failed/cancelled scan workspaces are deleted immediately; completed scans are retained per `BLINDSPOT_RETENTION_DAYS` (default 30). `DELETE /api/scans/{id}` removes the scan and its workspace.

## Evidence integrity (never fabricate)

This is a hard platform rule, enforced by the rule framework and the AI pipeline:

- Every finding must cite **real evidence**: an actual file path inside the analyzed APK and **real 1-based line numbers** with an excerpt from that location.
- Rule authors return `Evidence` objects built from files the rule actually read. A rule that cannot locate evidence must return `NEEDS_REVIEW` or `ERROR`, not a guess.
- **Severity and confidence are independent dimensions.** Severity = impact if exploited. Confidence = how certain the evidence is. A high-severity finding with low confidence is normal and must be displayed as such - severity must never be inflated to compensate for weak evidence.
- `PASS` means "this check found nothing", never "this app is secure". Reports state coverage limitations explicitly.

## AI hallucination controls

The optional Ollama review exists to *suggest*, never to *conclude*:

1. **Chunking** - at most `BLINDSPOT_AI_MAX_FILES` (default 12) files, `BLINDSPOT_AI_MAX_CHARS_PER_FILE` (default 4000) chars each, prioritized by a suspicion score - the model only ever sees bounded, real code.
2. **Schema validation** - model output must parse as JSON matching the expected finding schema; malformed output is discarded, not repaired by guessing.
3. **Evidence verification** - every AI-claimed file/line is checked against the actual workspace; claims pointing at non-existent locations are dropped.
4. **Corroboration only** - an AI suggestion within ±3 lines of a deterministic finding becomes corroboration (`ai-corroborated`); anything else is stored as an `AIReview` hypothesis row, labeled as such.
5. **Never promoted** - AI hypotheses can never set a finding to `confirmed`; only a human triage action does that.
6. **Graceful absence** - if Ollama is unreachable, the `ai_review` stage records a limitation and the scan completes normally.

## What Blindspot does not promise

- Static analysis only: no runtime behavior, no dynamic instrumentation.
- Findings are leads with evidence, not proof of exploitability - validate before acting.
- Missing optional tools (JADX, apktool, Ollama) reduce coverage; every scan's limitations list tells you exactly what was skipped.
