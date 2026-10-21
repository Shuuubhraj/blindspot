"""Unit tests for on-demand AI verify/fix (Ollama mocked - no model needed)."""
import json

import blindspot.ai.ondemand as od
from blindspot.ai import ondemand


class _FakeClient:
    def __init__(self, payload: dict | None, available: bool = True):
        self._payload = payload
        self._available = available

    def is_available(self):
        return self._available

    def list_models(self):
        return ["qwen2.5-coder:7b"]

    def generate(self, model, prompt, timeout_s=300, **kw):
        assert "UNTRUSTED" in prompt  # prompt-injection guard present
        return json.dumps(self._payload)


def _finding():
    return {
        "title": "MD5 in security context",
        "rule_id": "BS-C01",
        "severity": "high",
        "file_path": "src/Main.java",
        "line_start": 10,
        "line_end": 10,
        "description": "MD5 used for passwords",
        "snippet": 'MessageDigest.getInstance("MD5")',
        "remediation": "Use SHA-256",
    }


def _patch(monkeypatch, payload, available=True):
    monkeypatch.setattr(ondemand, "OllamaClient", lambda url: _FakeClient(payload, available))


def test_verify_true_positive(monkeypatch):
    _patch(monkeypatch, {"verdict": "true_positive", "reasoning": "MD5 is broken."})
    out = od.verify_finding(_finding(), model="m")
    assert out["verdict"] == "true_positive"
    assert "MD5" in out["reasoning"]
    assert out["model"] == "m"


def test_verify_false_positive(monkeypatch):
    _patch(monkeypatch, {"verdict": "false_positive", "reasoning": "Just a cache key."})
    out = od.verify_finding(_finding(), model="m")
    assert out["verdict"] == "false_positive"


def test_verify_bad_verdict_rejected(monkeypatch):
    _patch(monkeypatch, {"verdict": "maybe"})
    out = od.verify_finding(_finding(), model="m")
    assert "error" in out


def test_verify_model_unavailable(monkeypatch):
    _patch(monkeypatch, None, available=False)
    out = od.verify_finding(_finding(), model="m")
    assert "error" in out


def test_fix_returns_code(monkeypatch):
    _patch(monkeypatch, {
        "fixed_code": 'MessageDigest.getInstance("SHA-256")',
        "explanation": "SHA-256 resists collisions.",
        "caveats": "Use bcrypt for passwords.",
    })
    out = od.fix_finding(_finding(), model="m")
    assert "SHA-256" in out["fixed_code"]
    assert out["caveats"]


def test_fix_empty_code_rejected(monkeypatch):
    _patch(monkeypatch, {"fixed_code": "   ", "explanation": "x"})
    out = od.fix_finding(_finding(), model="m")
    assert "error" in out


def test_no_em_dashes_in_output(monkeypatch):
    _patch(monkeypatch, {
        "verdict": "true_positive",
        "reasoning": "Bad — really bad — code.",
    })
    out = od.verify_finding(_finding(), model="m")
    assert "—" not in out["reasoning"]
