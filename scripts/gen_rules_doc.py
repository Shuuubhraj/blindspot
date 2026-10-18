#!/usr/bin/env python3
"""Generate docs/RULES.md from the live rule registry.

Usage:  PYTHONPATH=backend .venv/bin/python scripts/gen_rules_doc.py
Writes docs/RULES.md. Never hand-edit the generated tables - regenerate.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from blindspot.rules.registry import all_rules  # noqa: E402


def _sev(r) -> str:
    v = r.default_severity
    return v.value if hasattr(v, "value") else str(v)


def _cell(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        return ", ".join(str(x) for x in v)
    s = str(v).replace("|", "\\|").replace("\n", " ")
    return s


def main() -> None:
    rules = sorted(all_rules(), key=lambda r: r.id)
    assert len(rules) >= 100, f"expected 100+ rules, got {len(rules)}"
    ids = [r.id for r in rules]
    assert len(set(ids)) == len(ids), "duplicate rule IDs"

    sev_counts = Counter(_sev(r) for r in rules)
    cat_counts = Counter(r.category for r in rules)

    lines = [
        "# Blindspot detection rules",
        "",
        f"**{len(rules)} rules**, generated from the live registry "
        "(`scripts/gen_rules_doc.py`). Do not hand-edit the tables below - regenerate.",
        "",
        "Severity distribution: "
        + ", ".join(f"{k}: {sev_counts[k]}" for k in
                    ("critical", "high", "medium", "low", "informational") if k in sev_counts),
        "",
        "Rules per category: "
        + ", ".join(f"{k}: {cat_counts[k]}" for k in sorted(cat_counts)),
        "",
        "Notes:",
        "- **Severity** is the default impact rating; **confidence** is assigned per",
        "  finding at scan time and is an independent dimension (see `docs/SECURITY.md`).",
        "- **OWASP** maps to the OWASP Mobile Top 10: 2024 (M1–M10).",
        "- **MASVS** uses verified category codes only (`MSTG-*`); numbered IDs are",
        "  never invented.",
        "",
        "| ID | Title | Category | Severity | OWASP | MASVS | Description |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rules:
        lines.append(
            f"| `{r.id}` | {_cell(r.title)} | {_cell(r.category)} | {_sev(r)} "
            f"| {_cell(r.owasp)} | {_cell(r.masvs)} | {_cell(r.description)} |"
        )
    out = ROOT / "docs" / "RULES.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(rules)} rules)")


if __name__ == "__main__":
    main()
