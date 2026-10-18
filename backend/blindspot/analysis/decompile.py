"""Decompilation adapters: JADX and apktool.

Both are optional. When unavailable the pipeline records a clear note and
continues with manifest/resource-level analysis - a scan is never failed
just because a decompiler is missing.
"""

from __future__ import annotations

import shutil
import threading
from pathlib import Path

from .tools import run_command

JADX_FLAGS_DOC = "jadx -d <outdir> --no-res <apk> (per JADX CLI documentation)"
APKTOOL_FLAGS_DOC = "apktool d -f -o <outdir> <apk> (per apktool documentation)"


def try_jadx(
    apk_path: Path,
    out_dir: Path,
    timeout_s: int = 600,
    cancel: threading.Event | None = None,
) -> tuple[Path | None, str]:
    """Decompile with JADX. Returns (sources_dir|None, note)."""
    if shutil.which("jadx") is None:
        return None, ("jadx not installed - Java/Kotlin decompilation skipped. "
                      "Install from https://github.com/skylot/jadx to enable it.")
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = ["jadx", "-d", str(out_dir), "--no-res", str(apk_path)]
    rc, _out, err = run_command(argv, timeout_s, cancel=cancel)
    if cancel is not None and cancel.is_set():
        return None, "jadx cancelled"
    if rc != 0:
        return None, f"jadx failed (rc={rc}): {err[-300:]}"
    sources = out_dir / "sources"
    root = sources if sources.is_dir() else out_dir
    java_files = list(root.rglob("*.java"))
    if not java_files:
        return None, "jadx ran but produced no .java files"
    return root, f"jadx decompiled {len(java_files)} java files"


def try_apktool(
    apk_path: Path,
    out_dir: Path,
    timeout_s: int = 600,
    cancel: threading.Event | None = None,
) -> tuple[Path | None, str]:
    """Decode with apktool (manifest, resources, smali). Returns (dir|None, note)."""
    if shutil.which("apktool") is None:
        return None, ("apktool not installed - resource/smali decoding skipped. "
                      "Install from https://apktool.org to enable it.")
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = ["apktool", "d", "-f", "-o", str(out_dir), str(apk_path)]
    rc, _out, err = run_command(argv, timeout_s, cancel=cancel)
    if cancel is not None and cancel.is_set():
        return None, "apktool cancelled"
    if rc != 0:
        return None, f"apktool failed (rc={rc}): {err[-300:]}"
    return out_dir, "apktool decoded resources and smali"
