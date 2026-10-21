# Blindspot architecture

## Components

```
┌─────────────┐      ┌──────────────┐      ┌──────────────────┐
│   Console   │◄────►│   FastAPI    │◄────►│   Orchestrator   │
│ React+TS    │ HTTP │  api/app.py  │ call │ pipeline/        │
│ (served /)  │ SSE  │              │      │ orchestrator.py  │
└─────────────┘      └──────────────┘      └────────┬─────────┘
                                                   │ stages
        ┌──────────────┬──────────────┬─────────────┴──────────────┐
        ▼              ▼              ▼                            ▼
  analysis/axml.py  analysis/     tools.py:                 rules/ (200)
  (own binary-      manifest.py    mobsfscan/              Rule subclasses
   manifest codec)  apk.py        jadx/apktool adapters      + registry
                                              │
                                              ▼
                                   ai/ (Ollama, optional) → reports/
                                   HTML / PDF / JSON
SQLite (SQLAlchemy) persists Scan / Finding / RuleExecution / StageRun / AIReview.
```

## Pipeline stages

`STAGES = ["validate", "extract", "metadata", "decompile", "third_party", "custom_rules", "ai_review", "normalize", "finalize"]`

| Stage | What happens |
|---|---|
| `validate` | Magic-byte check (`PK\x03\x04`), ZIP integrity, SHA-256, size guards |
| `extract` | Safe unzip into an isolated workspace (zip-slip guarded, file-count and byte caps) |
| `metadata` | Manifest decode (own AXML decoder; androguard as optional enrichment), package/version/SDK/components/permissions |
| `decompile` | JADX → Java/Kotlin sources (graceful skip when not installed) |
| `mobsfscan` | MobSFScan static analysis over decompiled sources (non-fatal) |
| `custom_rules` | all 200 registry rules against the scan context |
| `ai_review` | optional local Ollama pass (non-fatal) |
| `normalize` | cross-engine dedup + provenance merge |
| `finalize` | counts, limitations, report-ready state |

Each stage is wrapped in `_stage(scan_id, name, fatal=...)`: non-fatal stage failures are recorded as limitations and the scan continues. Progress (stage, percent, checks run, findings so far, elapsed) is published to an in-memory event bus consumed by the SSE endpoint `/api/scans/{id}/events`.

**Cancellation** is cooperative: a per-scan `threading.Event` is checked between stages and inside long tool runs; failed/cancelled scans have their workspaces deleted.

## Workspace isolation

Every scan gets `workspaces/<scan_id>/` with `uploads/`, `extract/`, `jadx/`, `third_party/` subdirs. The upload is written under its scan id, extraction never follows symlinks, and entries resolving outside the workspace root are rejected (zip-slip protection). Workspaces are removed on failed/cancelled scans; `BLINDSPOT_RETENTION_DAYS` (default 30) governs completed-scan retention.

## DB models (`core/models.py`)

- `Scan` - id, file name, sha256, size, status (`queued|running|completed|failed|cancelled`), config JSON, counts, limitations, timestamps
- `Finding` - scan FK, engine (`custom|mobsf|ai`), rule id, title, severity, confidence, description, file path, line range, snippet, CWE/OWASP/MASVS, remediation, provenance (JSON list), validation status, review status (`open|confirmed|rejected|accepted_risk|needs_review`) + note
- `RuleExecution` - per-rule outcome (`pass|finding|needs_review|not_applicable|error|not_run`), duration
- `StageRun` - per-stage status, started/finished, notes
- `AIReview` - raw AI output rows kept for audit

## Rule framework (`rules/base.py`)

```python
class Rule:                       # subclass, set class attrs, implement check()
    id = "BS-M01"                 # unique, stable
    title = "..."
    description / remediation / references
    default_severity: Severity    # critical|high|medium|low|informational
    owasp: "M1".."M10"            # OWASP Mobile Top 10: 2024
    masvs: "MSTG-STORAGE" | ...   # verified category codes only - never invented IDs
    cwe: [...]
    def check(self, ctx: ScanContext) -> RuleResult: ...

class RuleResult:
    status: RuleStatus             # PASS | FINDING | NEEDS_REVIEW |
                                  # NOT_APPLICABLE | ERROR | NOT_RUN
    evidence: list[Evidence]      # file_path + 1-based line_start/line_end + excerpt
    confidence: Confidence        # high|medium|low - INDEPENDENT of severity
```

`Rule.run()` wraps `check()` with timing, exception capture (→ `ERROR`), and the not-applicable gate. `PASS` means "this check found nothing" - never "the app is safe". Evidence must reference real files and real line numbers; fabricated evidence is a framework violation.

MASVS is restricted to the verified category codes (`MSTG-STORAGE/CRYPTO/AUTH/NETWORK/PLATFORM/CODE/RESILIENCE`); numbered MASVS IDs are never invented.

## Dedup strategy (`pipeline/orchestrator.py`)

1. **Cross-engine merge** - conservative: a new finding merges into an existing row only on exact `(file_path, line_start)` match. The merged row keeps provenance entries from every engine (`[{engine, rule_id}, ...]`) and the highest severity wins.
2. **AI corroboration** - an AI-suggested finding that lands within **±3 lines** of a deterministic finding on the same file is attached as corroboration (`validation_status = "ai-corroborated"`) instead of creating a new row. AI suggestions with no deterministic neighbor are stored as `AIReview` rows, labeled as hypotheses, never promoted to confirmed findings.

## AXML parser (`analysis/axml.py`)

Real APKs store `AndroidManifest.xml` in Android's binary XML format. Blindspot ships its own minimal encoder/decoder rather than depending on a heavyweight parser for the critical path:

- Decodes: `RES_XML_TYPE`, `RES_STRING_POOL_TYPE` (UTF-16 and UTF-8), `START/END_NAMESPACE`, `START/END_ELEMENT` with typed attribute values
- Encodes: writes UTF-16 string pools - used to build the synthetic fixture APK deterministically
- Round-trip verified in unit tests; cross-validated against androguard on the fixture APK
- androguard remains an *optional enrichment* (e.g. additional resource decoding), never a hard dependency of manifest parsing
