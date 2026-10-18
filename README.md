<p align="center">
  <img src="assets/logo.svg" width="140" alt="Blindspot logo" />
</p>

<h1 align="center">Blindspot</h1>

<p align="center">
  <i>Find what others miss.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12-blue" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/react-18-61dafb" alt="React 18" />
  <img src="https://img.shields.io/badge/AI-ollama%20local-black" alt="Local Ollama AI" />
  <img src="https://img.shields.io/badge/local--first-100%25-green" alt="100% local-first" />
</p>

---

**Blindspot** is a local-first Android APK security assessment platform. Drop in an APK and get a real static-analysis security report: 120 original detection rules, OWASP Mobile Top 10 (2024) mapping, an optional on-device AI second opinion, and one-click HTML / PDF / JSON exports. Everything runs on your own machine. Nothing is uploaded anywhere.

Built by [@shuuubhraj](https://github.com/shuuubhraj).

## Features

**Analysis engine**
- 120 original, individually testable detection rules across 7 categories: manifest, storage, network, crypto, WebView, auth, platform
- Every rule mapped to the OWASP Mobile Top 10 (2024); all 10 categories covered
- Severity and confidence tracked as independent dimensions, each with a written rationale
- MobSFScan pattern analysis integrated with provenance-preserving cross-engine dedup
- Real evidence on every finding: actual file path, 1-based line numbers, source snippet. Nothing is ever fabricated

**Local AI review (optional)**
- On-device LLM second opinion via Ollama (e.g. `qwen2.5-coder:7b`). No cloud, no API keys, no data leaves the machine
- Hallucination controls: every AI proposal is validated against real code locations before it is kept; findings the static engines independently confirm are marked `ai-corroborated`; AI output never overrides a static-engine result
- Dedicated **AI Findings** page per scan: each AI finding as a full card with justification, proof of concept (file + line + code), impact, and remediation

**Console**
- Live scan view: pipeline stepper, live stats, and a real-time "Behind the scenes" engine feed that survives tab switches and highlights AI hits
- Findings explorer with search, filters, and severity/confidence sorting
- Manual review workflow: confirm, reject, accept risk, or mark needs-review, with notes
- Scan history (reopen, export, delete), browsable rule library, system status page with per-tool readiness
- Dark mode included

**Reports**
- One-click HTML, PDF, and JSON exports
- PDF mirrors the HTML report: metadata grid, executive summary, contents, scope and methodology, scan coverage, severity breakdown, OWASP table, dedicated AI review section, one page per finding

## Screenshots

| Live scan | Assessment overview |
|---|---|
| ![Live scan](screenshots/live-scan.jpg) | ![Assessment overview](screenshots/overview.jpg) |

| AI Findings | AI finding detail |
|---|---|
| ![AI Findings](screenshots/ai-findings.jpg) | ![AI finding detail](screenshots/ai-finding-detail.jpg) |

| Rule library | System status |
|---|---|
| ![Rule library](screenshots/rule-library.jpg) | ![System status](screenshots/system-status.jpg) |

| Scan history | AI setup |
|---|---|
| ![Scan history](screenshots/scan-history.jpg) | ![AI setup](screenshots/system-ai-setup.jpg) |

A full sample report (DIVA APK) is attached under [`samples/`](samples/blindspot-sample-report-diva.pdf).

## How it works

```
Upload APK → Validate → Extract → Metadata → Decompile (JADX + apktool)
    → MobSFScan → 120 custom rules → AI review (optional) → Report
```

- The manifest is decoded with Blindspot's own binary AXML parser; androguard enriches where available
- Decompilation runs JADX and apktool in parallel when installed; the pipeline degrades gracefully and reports honest limitations when a tool is missing
- Each pipeline stage streams live progress to the console over server-sent events

## Installation

### Requirements

- Python 3.12+
- Node.js 18+ (only needed if you want to rebuild the console; a prebuilt bundle ships in `frontend/dist/`)
- Java 17+ (only for JADX/apktool decompilation)
- Optional: [JADX](https://github.com/skylot/jadx) and [apktool](https://apktool.org/) on your `PATH` for decompiled-source analysis
- Optional: [Ollama](https://ollama.com/) with a code model (e.g. `qwen2.5-coder:7b`) for the AI review

### Setup (Windows PowerShell)

```powershell
cd blindspot\backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
```

### Setup (Linux / macOS)

```bash
cd blindspot/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

No extra install flags are needed. The PDF engine (ReportLab) is pure Python, so there are no system libraries to install on any platform.

## Usage

### Start the console

```powershell
# Windows
cd blindspot\backend; .venv\Scripts\Activate.ps1; blindspot serve
```

```bash
# Linux / macOS
cd blindspot/backend && source .venv/bin/activate && blindspot serve
```

Then open **http://127.0.0.1:8000**. Upload an APK and watch the assessment run live.

### CLI

```bash
blindspot serve                          # start the API + console
blindspot scan app.apk                   # scan an APK from the terminal
blindspot scan app.apk --no-ai           # scan without the AI review
blindspot status <scan-id>               # check scan progress
blindspot findings <scan-id>             # list findings
blindspot report <scan-id> --format pdf  # export HTML / PDF / JSON
blindspot rules                          # list the 120 detection rules
blindspot system                         # tool readiness and limits
```

### Enable the AI review

1. Install Ollama and start it (it listens on `http://127.0.0.1:11434` by default)
2. Pull a code-capable model:
   ```bash
   ollama pull qwen2.5-coder:7b
   ```
3. Tick **AI review** on the upload page (or pass `--ai-model` on the CLI)

A quantized 3B-7B code model is a good starting point. Roughly: 3B needs ~4 GB RAM, 7B needs ~8 GB. Larger models improve review quality but slow the scan. If Ollama is unavailable, the scan simply continues with deterministic analysis only. No model is ever downloaded silently and there is no cloud fallback.

## Configuration

Environment variables (all optional):

| Variable | Default | Purpose |
|---|---|---|
| `BLINDSPOT_DATA_DIR` | `backend/blindspot/data/` | Where the SQLite DB, uploads, and workspaces live |
| `BLINDSPOT_AI_MODEL` | `qwen2.5-coder:7b` | Ollama model used for AI review |
| `BLINDSPOT_AI_MAX_FILES` | `12` | Max files the AI reviews per scan |
| `BLINDSPOT_AI_TIMEOUT_S` | `300` | Per-file AI timeout in seconds |
| `BLINDSPOT_AI_NUM_CTX` | `8192` | Ollama context window |
| `BLINDSPOT_AI_NUM_PREDICT` | `3000` | Cap on AI output tokens per file |

## Project structure

```
blindspot/
  backend/
    blindspot/          # FastAPI app, CLI, pipeline, rules, reports
      analysis/         # APK/AXML parsing, decompiler adapters, tool detection
      rules/            # 120 detection rules (BS-M/S/N/C/W/A/P)
      ai/               # Ollama client + review loop with hallucination controls
      pipeline/         # scan orchestrator (stages, SSE progress, cancellation)
      reports/          # HTML / PDF (ReportLab) / JSON exporters
    tests/              # 347 automated tests
  frontend/             # React + TypeScript + Tailwind console (prebuilt in dist/)
  docs/                 # Architecture, rule catalog, security model, troubleshooting
  screenshots/          # Console screenshots
  samples/              # Sample reports from real scans
  assets/               # Brand assets (logo)
```

## Troubleshooting

**`blindspot` command not found after install**
Activate the venv first (`.venv\Scripts\Activate.ps1` on Windows, `source .venv/bin/activate` on Linux/macOS), then run `pip install -e .` again from `backend/`.

**PowerShell refuses to run the activate script**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Decompilation stage is skipped**
Install Java 17+, then put `jadx` and `apktool` on your `PATH`. The System page shows per-tool readiness. Scans still complete without them; the report lists it as a limitation.

**AI review never starts / fails fast**
Check the System page: Ollama must be reachable at `http://127.0.0.1:11434` and a model must be pulled (`ollama list`). The scan continues with static analysis only if Ollama is down.

**AI review is slow**
That is the model thinking on your CPU, roughly ~2 minutes per file with a 7B model on CPU. Lower `BLINDSPOT_AI_MAX_FILES` for faster scans, or use a smaller model.

**Port 8000 already in use**
`blindspot serve --port 8123` (pick any free port).

**Scan history from a previous install**
Runtime data lives in `backend/blindspot/data/` (SQLite DB, uploads, workspaces). Delete that folder for a clean slate.

More detail: [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

## Design principles

- **Local-first.** The APK, the decompiled code, and the AI review never leave the machine.
- **Real results only.** Every finding carries verifiable evidence. No fabricated output, ever.
- **Honest about limits.** Missing tools and failed stages are reported as limitations, not silently skipped.
- **AI as a second opinion, not a verdict.** Hypotheses are labeled; static engines have the final word.

## Author

Built by **[@shuuubhraj](https://github.com/shuuubhraj)** - *"Find what others miss."*
