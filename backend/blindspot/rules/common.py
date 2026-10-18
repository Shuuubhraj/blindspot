"""Shared helpers for detection rules: safe file iteration and regex search.

All helpers are defensive: unreadable files, binary blobs and oversized
files are skipped, never fatal. Line numbers reported are real 1-based
numbers from the actual file bytes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from .base import Evidence, ScanContext

MAX_TEXT_BYTES = 1_000_000      # skip files larger than this
MAX_SNIPPET_CHARS = 2000        # cap evidence snippets

_TEXT_EXTS = {
    ".java", ".kt", ".kts", ".xml", ".json", ".properties", ".txt",
    ".js", ".html", ".gradle", ".cfg", ".ini", ".yaml", ".yml",
}


@dataclass
class Hit:
    path: Path
    line_no: int          # 1-based, real
    line: str
    match: re.Match


def read_text_capped(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> Optional[str]:
    """Read a file as text, returning None for binary/oversized/unreadable."""
    try:
        if path.stat().st_size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:  # binary heuristic on the head
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8", errors="replace")
        except OSError:
            return None


def iter_files(roots: list[Path], extensions: Optional[set[str]] = None) -> Iterator[Path]:
    """Yield files under roots, skipping hidden dirs and build noise."""
    exts = {e.lower() for e in extensions} if extensions else None
    for root in roots:
        if not root or not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            parts = path.parts
            if any(p.startswith(".") or p in {"build", "node_modules"} for p in parts):
                continue
            if exts is not None and path.suffix.lower() not in exts:
                continue
            yield path


def iter_source_files(ctx: ScanContext) -> Iterator[Path]:
    """Decompiled Java/Kotlin sources (jadx output or equivalent)."""
    yield from iter_files(ctx.java_roots, {".java", ".kt"})


def iter_text_artifacts(ctx: ScanContext) -> Iterator[Path]:
    """Decoded resources, assets and other text artifacts."""
    roots = [d for d in (ctx.res_dir, ctx.assets_dir) if d]
    yield from iter_files(roots, _TEXT_EXTS)


def iter_smali_files(ctx: ScanContext) -> Iterator[Path]:
    if ctx.smali_dir and ctx.smali_dir.is_dir():
        yield from iter_files([ctx.smali_dir], {".smali"})


def grep(
    pattern: str,
    files: Iterator[Path],
    flags: int = 0,
    max_hits: int = 500,
) -> list[Hit]:
    """Regex-search files line by line. Returns real line numbers."""
    rx = re.compile(pattern, flags)
    hits: list[Hit] = []
    for path in files:
        text = read_text_capped(path)
        if text is None:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            m = rx.search(line)
            if m:
                hits.append(Hit(path=path, line_no=i, line=line.rstrip("\n"), match=m))
                if len(hits) >= max_hits:
                    return hits
    return hits


def evidence_from_hit(
    ctx: ScanContext,
    hit: Hit,
    description: str = "",
    context_lines: int = 2,
) -> Evidence:
    """Build Evidence with a few surrounding lines for readability.

    The reported line_start/line_end always cover the real matched line.
    """
    rel = _rel(ctx, hit.path)
    snippet_lines: list[str] = []
    text = read_text_capped(hit.path)
    if text:
        lines = text.splitlines()
        lo = max(0, hit.line_no - 1 - context_lines)
        hi = min(len(lines), hit.line_no + context_lines)
        for n in range(lo, hi):
            marker = ">>>" if n == hit.line_no - 1 else "   "
            snippet_lines.append(f"{marker} {n + 1:5d} | {lines[n][:220]}")
    snippet = "\n".join(snippet_lines)[:MAX_SNIPPET_CHARS]
    return Evidence(
        file_path=rel,
        snippet=snippet,
        description=description or f"Matched `{hit.match.group(0)[:120]}`",
        line_start=hit.line_no,
        line_end=hit.line_no,
    )


def evidence_simple(
    ctx: ScanContext,
    path: Path | str,
    description: str,
    snippet: str = "",
    line_start: Optional[int] = None,
    line_end: Optional[int] = None,
) -> Evidence:
    p = Path(path)
    rel = _rel(ctx, p) if p.is_absolute() else str(path)
    return Evidence(
        file_path=rel,
        snippet=snippet[:MAX_SNIPPET_CHARS],
        description=description,
        line_start=line_start,
        line_end=line_end,
    )


def _rel(ctx: ScanContext, path: Path) -> str:
    try:
        return str(path.relative_to(ctx.workdir))
    except ValueError:
        return str(path)


def java_string_literals(text: str) -> list[tuple[int, str]]:
    """Extract (line_no, literal) for double-quoted Java/Kotlin strings."""
    out: list[tuple[int, str]] = []
    # crude but effective; avoids matching across lines
    for i, line in enumerate(text.splitlines(), start=1):
        for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', line):
            out.append((i, m.group(1)))
    return out


def looks_like_secret(value: str) -> bool:
    """Heuristic: high-entropy / structured secret-looking string."""
    v = value.strip()
    if len(v) < 12:
        return False
    structured = (
        v.startswith("AKIA") or v.startswith("ghp_") or v.startswith("gho_")
        or v.startswith("xox") or v.startswith("sk-") or v.startswith("AIza")
        or v.startswith("-----BEGIN ") or "api_key" in v.lower()
    )
    if structured:
        return True
    # Shannon entropy over the charset
    import math
    from collections import Counter
    if len(v) < 16:
        return False
    freq = Counter(v)
    entropy = -sum((c / len(v)) * math.log2(c / len(v)) for c in freq.values())
    return entropy > 4.2 and len(v) >= 20
