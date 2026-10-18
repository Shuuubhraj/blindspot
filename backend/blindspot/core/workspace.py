"""Isolated scan workspaces and safe archive extraction.

Every scan gets a unique workspace directory. Extraction defends against:
  - ZIP path traversal (absolute paths, "..")
  - decompression bombs (total size cap, per-file cap, file count cap)
  - symlink abuse (symlink entries are skipped, never followed)

The uploaded APK is untrusted input: it is never executed, only read.
"""

from __future__ import annotations

import os
import shutil
import stat
import uuid
import zipfile
from pathlib import Path

from ..config import settings


def make_workspace(scan_id: str | None = None) -> tuple[str, Path]:
    """Create an isolated workspace. Returns (scan_id, path)."""
    scan_id = scan_id or uuid.uuid4().hex
    # scan_id is hex-only: safe to use as a path component
    if not scan_id.replace("-", "").isalnum():
        raise ValueError("invalid scan id")
    path = settings.workspace_root / scan_id
    path.mkdir(parents=True, exist_ok=False)
    (path / "extracted").mkdir(exist_ok=True)
    return scan_id, path


def cleanup_workspace(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


def is_within_directory(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def safe_extract_zip(
    zip_path: Path,
    dest: Path,
    max_total_bytes: int | None = None,
    max_files: int | None = None,
) -> list[str]:
    """Extract a zip safely. Returns sorted list of relative paths.

    Raises ValueError on traversal, symlink, bomb or corrupt archive.
    """
    max_total = max_total_bytes or settings.max_extract_mb * 1024 * 1024
    max_n = max_files or settings.max_extract_files
    extracted: list[str] = []
    total = 0
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > max_n:
            raise ValueError(f"archive has {len(infos)} entries (limit {max_n})")
        for info in infos:
            name = info.filename
            if not name or name.endswith("/"):
                continue
            # traversal defense: reject absolute paths and ".." segments
            parts = Path(name).parts
            if Path(name).is_absolute() or ".." in parts:
                raise ValueError(f"unsafe zip entry (path traversal): {name!r}")
            # symlink defense: skip symlink entries entirely
            if stat.S_ISLNK(info.external_attr >> 16):
                continue
            # bomb defense: per-entry uncompressed size
            if info.file_size > max_total:
                raise ValueError(f"zip entry too large: {name!r} ({info.file_size} bytes)")
            total += info.file_size
            if total > max_total:
                raise ValueError(
                    f"archive uncompressed size exceeds {max_total} bytes (bomb suspected)")
            target = dest / Path(*parts)
            if not is_within_directory(dest, target):
                raise ValueError(f"zip entry escapes destination: {name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 256)
            extracted.append(str(Path(*parts)).replace(os.sep, "/"))
    return sorted(extracted)
