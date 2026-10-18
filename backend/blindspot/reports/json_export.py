"""JSON report export: machine-readable full assessment."""

from __future__ import annotations

import json

from .common import build_report_data


def render_json(scan_id: str) -> str | None:
    data = build_report_data(scan_id)
    if data is None:
        return None
    data["generator"] = "blindspot"
    data["format_version"] = "1.0"
    return json.dumps(data, indent=2, default=str)
