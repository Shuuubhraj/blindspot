# Blindspot - Final Build Summary (§20)

**"Find what others miss."** - Blindspot is a production-minded, local-first Android APK
security assessment platform: upload an APK, get a real static-analysis security report
with code evidence, OWASP Mobile Top 10: 2024 mapping, and one-click HTML/PDF/JSON exports.
Everything runs on your own machine; nothing is uploaded anywhere.

Repo: `~/workspace/blindspot-mobile/` · CLI: `blindspot` · Console: "Blindspot Security Console"

---

## Recent refinements (2026-10-18)

- **Em-dash ban**: house style now forbids em-dashes everywhere - swept all 245 occurrences from code, UI, reports and docs; AI model output is sanitized on ingest (`validate_ai_finding`), so the model can never sneak one into a finding.
- **Feed backfill**: "Behind the scenes" no longer goes blank when you navigate away and back mid-scan - it reloads the persisted scan log on mount. Pipeline milestone messages are now written to the scan log as they happen.
- **AI finding highlight**: feed entries where the AI accepts new findings ("N finding(s) accepted") are tinted emerald in the real-time log so they catch your eye.
- **AI Findings page**: new per-scan route `/scans/{id}/ai-findings` - every AI finding as a full card with severity/validation badges, the finding (incl. why-it-is-unsafe and preconditions), proof of concept (file:line + code), impact, remediation, OWASP/CWE. Linked from Overview and the Findings explorer.
- **PDF rebuilt to match the HTML report**: title block, 3-column metadata box grid, executive summary, contents, scope and methodology, APK metadata, scan coverage, tinted severity boxes, OWASP table, dedicated AI review section, one page per finding (AI findings get a purple AI badge), limitations.
- **Favicon**: now the white rounded-square eye matching the console logo.
- AI finding descriptions are richer: the model's `why_unsafe` and `preconditions` fold into the stored description as labeled sections, so they show in the UI and all reports.
- 542 tests pass.

## 1. What was implemented (§1–§19)

| # | Spec section | Status |
|---|---|---|
| 1 | Local-first, upload → assess → review → export flow | ✅ Done - FastAPI backend, React console, `blindspot` CLI |
| 2 | Dashboard "Blindspot Security Console" | ✅ Done - 7 routes: Upload, Live scan, Overview, Findings, History, Rules, System |
| 3 | CLI `blindspot` | ✅ Done - `serve`, `scan`, `status`, `findings`, `report`, `rules`, `system` (all verified end-to-end) |
| 4 | Real analysis only, never fabricate | ✅ Enforced - every finding carries real file path + 1-based line numbers + source snippet; evidence spot-verified byte-for-byte against source |
| 5 | 100+ individually testable checks | ✅ Done - **200 rules**, each with its own unit tests (vuln → finding, clean → pass) |
| 6 | OWASP Mobile Top 10: 2024 mapping | ✅ Done - all 200 rules mapped to M1–M10, all 10 categories covered |
| 7 | Severity × confidence as independent dimensions | ✅ Done - separate fields on every rule and finding, each with written rationale |
| 8 | Real APK parsing (manifest, DEX, resources) | ✅ Done - own binary AXML encoder/decoder (round-trip verified; androguard independently parses our output), androguard enrichment |
| 9 | Decompilation (JADX/apktool adapters) | ✅ Done - adapters written, degrade gracefully when tools absent (honest limitations in every report) |
| 10 | Third-party engine (mobsfscan) | ✅ Done - integrated with provenance-preserving dedup (semgrep removed in v5: no Windows support) |
| 11 | Custom rule engine | ✅ Done - `Rule` base class, 6 result statuses, evidence framework, registry |
| 12 | Local AI review (Ollama) with hallucination controls | ✅ Done - chunking, schema validation, dedup, ±3-line corroboration; AI hypotheses labeled, never promoted to confirmed |
| 13 | Findings review workflow | ✅ Done - confirmed / rejected / accepted-risk / needs-review + notes |
| 14 | HTML/PDF/JSON exports | ✅ Done - self-contained HTML (no external resources), ReportLab PDF, versioned JSON |
| 15 | Scan history, reopen, delete | ✅ Done - SQLite persistence, history page, 30-day retention |
| 16 | System status & limits | ✅ Done - per-tool readiness cards, resource limits, Ollama setup hints |
| 17 | Automated tests | ✅ Done - **542 tests pass** |
| 18 | Full docs | ✅ Done - README, ARCHITECTURE, SECURITY, RULES (generated from registry), MODEL_SETUP, TROUBLESHOOTING, .env.example, docker-compose.yml, install-deps.sh |
| 19 | Sample reports | ✅ Done - `samples/` has HTML + PDF + JSON from a real fixture scan |

## 2. Stack

- **Backend:** Python 3.12, FastAPI, Pydantic, SQLAlchemy + SQLite, SSE live progress, Typer CLI
- **Frontend:** React 18 + TypeScript + Vite 5 + Tailwind CSS 3, dark mode, served by the API
- **Analysis:** custom AXML parser, androguard 4.1.4, mobsfscan, JADX/apktool adapters
- **AI:** Ollama, local-only, optional
- **Reports:** Jinja2 → HTML, ReportLab → PDF (pure Python, no system libs)

## 3. Install / launch / test

```bash
cd blindspot-mobile/backend
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
blindspot serve                      # API + console at http://127.0.0.1:8000
blindspot scan app.apk               # full assessment from the terminal
blindspot report <scan-id> --format pdf -o report.pdf
pytest tests/                        # 542 tests
# console dev mode:
cd ../frontend && npm install && npm run dev
```

## 4. Checks list (200 rules)

- **Manifest (BS-M01–M20):** debuggable, allowBackup, cleartext, SDK levels, dangerous-permission groups, exported components without guards, task hijacking, backup rules, query-all-packages…
- **Storage (BS-S01–S25):** hardcoded secrets/keys, PEM/keystore files, world-readable modes, external storage, insecure SharedPreferences/SQLite/cache/logs/clipboard, FileProvider paths, backup includes…
- **Network (BS-N01–N35):** cleartext HTTP, TLS validation bypasses, pinning absence, insecure WebSocket, hardcoded IPs/URLs, proxy leakage…
- **Crypto (BS-C01–C15):** MD5/SHA-1, DES/3DES/RC4, ECB, hardcoded keys/IVs, insecure Random, short RSA, custom XOR crypto, CBC without integrity…
- **WebView & injection (BS-W01–W30):** JS bridges, file-URL access, mixed content, JS injection sinks, SQLi, command injection, path traversal, deserialization, dynamic code loading…
- **Auth (BS-A01–A15):** client-side authz, hardcoded bypass, test accounts, plaintext tokens, token expiry, secrets in logs, weak PIN, biometric fallback…
- **Platform (BS-P01–P20):** deep-link hijacking, intent spoofing, exported receivers/providers, tapjacking, overlay, clipboard, debuggable WebView, native code loading, supply-chain…
- **Secrets (BS-X01–X20):** cloud and API keys (AWS, Google, Stripe, Slack, GitHub, Firebase), JWTs, PEM private keys, keystore passwords, OAuth client secrets, credentials in URLs and Gradle files…
- **Supply chain (BS-D01–D20):** ad/analytics/crash/payment SDK fingerprinting, vulnerable library versions, packer and obfuscation detection, Flutter/React Native/Cordova/Unity/Xamarin detection, tracker census…

Full table with severities and OWASP mappings: `docs/RULES.md` (regenerate with `scripts/gen_rules_doc.py`).

## 5. Unavailable optionals (not installed in this environment)

- **JADX** - Java/Kotlin decompilation skipped; custom rules still run on any provided sources. Install: https://github.com/skylot/jadx
- **apktool** - resource/smali decoding skipped. Install: https://apktool.org
- **aapt2** - not required (own AXML parser is primary)
- **Ollama** - AI review stage skips gracefully with a setup hint. Install: `ollama serve` + `ollama pull qwen2.5-coder:7b`
- **Docker** - `docker-compose.yml` is provided but untested here (no Docker in this environment)

Every report lists exactly which tools were missing, so coverage gaps are never silent.

## 6. Known limitations

1. **Static analysis only** - no dynamic instrumentation; findings are code-evidence based, some are NEEDS_REVIEW by design.
2. **Heuristic rules state what they can't prove** (e.g., server-side authz) in their confidence rationale.
3. **mobsfscan upstream default** skips paths containing `fixtures`/`spec`/`.git` - documented in TROUBLESHOOTING; irrelevant for real APK decompilation output.
4. **AI review is advisory** - hypotheses are labeled and never merged into confirmed findings without corroboration.
6. **Tight-memory environments** (this build ran on 2 CPUs / ~600 MB free RAM) - scans are sequential by default; large APKs take longer.
7. Line-based heuristics can miss multi-line call arguments - noted per rule.
