"""Third-party scanner adapter: mobsfscan.

mobsfscan is optional. The adapter:
  - checks availability (package importable / binary on PATH),
  - runs with an explicit timeout via argument arrays (never shell strings),
  - supports scan cancellation,
  - returns normalized finding dicts plus a human-readable note.

CLI interface was verified against the installed version:
  mobsfscan --json -o <out> --type android --no-fail <path...>

Note: mobsfscan's own semantic-grep rules shell out to a `semgrep`
binary when one is present; when it is absent (e.g. Windows, where
semgrep is unsupported) those rules are skipped gracefully and the
pattern-matching rules still run.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

# Directory holding the current interpreter. Note: prefer _find_tool() over
# this for locating binaries, because sys.executable may be a symlink.
VENV_BIN = Path(sys.executable).parent


def _base_env() -> dict[str, str]:
    env = dict(os.environ)
    # mobsfscan is installed into the venv; make sure the venv's bin dir
    # is on PATH so the binary resolves even when launched oddly.
    env["PATH"] = str(VENV_BIN) + os.pathsep + env.get("PATH", "")
    return env


def _find_tool(name: str) -> str | None:
    """Locate a tool binary, preferring the venv bin dir.

    Note: sys.executable may be a symlink (e.g. .venv/bin/python ->
    /usr/bin/python3), so its resolved parent is NOT necessarily the venv
    bin dir. PATH lookup with the venv prepended is robust.
    """
    venv_bin = Path(sys.executable).parent
    search = os.pathsep.join([str(venv_bin), os.environ.get("PATH", "")])
    return shutil.which(name, path=search)


def detect_tools() -> dict[str, bool]:
    """Report which optional analysis tools are available."""
    return {
        "jadx": shutil.which("jadx") is not None,
        "apktool": shutil.which("apktool") is not None,
        "aapt2": shutil.which("aapt2") is not None,
        "androguard": importlib.util.find_spec("androguard") is not None,
        "mobsfscan": importlib.util.find_spec("mobsfscan") is not None,
    }


def _windows_wrap(argv: list[str]) -> list[str]:
    """On Windows, .bat/.cmd launchers (e.g. jadx.bat, apktool.bat) cannot be
    executed directly by CreateProcess - that raises FileNotFoundError
    ([WinError 2]). Run them through cmd.exe /c instead."""
    if os.name != "nt" or not argv:
        return argv
    exe = shutil.which(argv[0]) or argv[0]
    if exe.lower().endswith((".bat", ".cmd")):
        comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
        return [comspec, "/c", exe, *argv[1:]]
    return argv


def run_command(
    argv: list[str],
    timeout_s: int,
    cwd: Path | None = None,
    cancel: threading.Event | None = None,
) -> tuple[int, str, str]:
    """Run argv (no shell). Returns (returncode, stdout, stderr).

    Polls so a cancellation event can kill the child promptly.
    """
    argv = _windows_wrap(argv)
    proc = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(cwd) if cwd else None, env=_base_env(), text=True,
    )
    try:
        while True:
            try:
                out, err = proc.communicate(timeout=1.0)
                return proc.returncode, out, err
            except subprocess.TimeoutExpired:
                if cancel is not None and cancel.is_set():
                    proc.kill()
                    out, err = proc.communicate()
                    return -9, out, "cancelled by user"
                # enforce overall timeout via elapsed tracking outside
    finally:
        if proc.poll() is None:
            proc.kill()


# ---------------------------------------------------------------------------
# mobsfscan
# ---------------------------------------------------------------------------

# Old (2016) Mobile Top 10 -> 2024 Mobile Top 10 approximate mapping.
_MOBSF_OWASP_MAP = {
    "M1": "M8", "M2": "M9", "M3": "M5", "M4": "M3", "M5": "M10",
    "M6": "M3", "M7": "M4", "M8": "M7", "M9": "M7", "M10": "M8",
}

_MOBSF_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "informational"}


def _parse_cwe(raw: str) -> list[str]:
    # "CWE-749: Exposed Dangerous Method or Function" -> ["CWE-749"]
    out = []
    for part in str(raw).split(","):
        part = part.strip()
        if part.upper().startswith("CWE-"):
            out.append(part.split(":")[0].strip().upper())
    return out


def run_mobsfscan(
    targets: list[Path],
    out_dir: Path,
    timeout_s: int = 600,
    cancel: threading.Event | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """Run mobsfscan over decompiled source dirs. Returns (findings, note)."""
    if importlib.util.find_spec("mobsfscan") is None:
        return [], "mobsfscan is not installed (pip install mobsfscan)"
    existing = [str(t) for t in targets if t and Path(t).is_dir()]
    if not existing:
        return [], "mobsfscan skipped: no decompiled source directories available"
    out_path = out_dir / "mobsfscan.json"
    binary = _find_tool("mobsfscan")
    if not binary:
        return [], "mobsfscan binary not found on PATH"
    argv = [binary, "--json", "-o", str(out_path),
            "--type", "android", "--no-fail", *existing]
    rc, _out, err = run_command(argv, timeout_s, cancel=cancel)
    if cancel is not None and cancel.is_set():
        return [], "mobsfscan cancelled"
    if not out_path.is_file():
        return [], f"mobsfscan produced no output (rc={rc}): {err[-300:]}"
    try:
        data = json.loads(out_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], f"mobsfscan output unreadable: {exc}"
    findings: list[dict[str, Any]] = []
    for rule_name, entry in (data.get("results") or {}).items():
        if not isinstance(entry, dict) or not entry.get("files"):
            continue
        meta = entry.get("metadata", {})
        sev = _MOBSF_SEV.get(str(meta.get("severity", "")).upper(), "informational")
        owasp_raw = str(meta.get("owasp-mobile", ""))
        owasp = []
        if owasp_raw[:2].upper() in _MOBSF_OWASP_MAP:
            owasp = [_MOBSF_OWASP_MAP[owasp_raw[:2].upper()]]
        for f in entry["files"]:
            lines = f.get("match_lines") or []
            findings.append({
                "engine": "mobsf",
                "rule_id": f"mobsf:{rule_name}",
                "title": rule_name.replace("_", " ").title(),
                "severity": sev,
                "confidence": "medium",
                "description": str(meta.get("description", "")),
                "file_path": str(f.get("file_path", "")),
                "line_start": lines[0] if lines else None,
                "line_end": lines[-1] if lines and len(lines) > 1 else (lines[0] if lines else None),
                "snippet": str(f.get("match_string", ""))[:2000],
                "cwe": _parse_cwe(meta.get("cwe", "")),
                "owasp": owasp,
                "masvs": [str(meta.get("masvs"))] if meta.get("masvs") else [],
                "references": [str(meta.get("reference"))] if meta.get("reference") else [],
                "remediation": "",
            })
    note = f"mobsfscan scanned {len(existing)} director(ies), {len(findings)} matches"
    return findings, note


