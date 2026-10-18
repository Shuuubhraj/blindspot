"""Blindspot rule framework.

Typed data structures shared by every detection rule, the orchestrator,
the AI review engine and the report generators.

A Rule is a small, independently testable unit. It inspects a ScanContext
and returns a RuleResult whose status is one of:

  PASS            check ran, no issue detected
  FINDING         evidence indicates a potential/confirmed security issue
  NEEDS_REVIEW    ambiguous condition needing contextual review
  NOT_APPLICABLE  check does not apply to this APK
  ERROR           check failed to execute
  NOT_RUN         check was not executed

Severity (impact if real) and Confidence (strength of evidence) are always
independent dimensions. Never treat PASS as proof a vulnerability is
impossible.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleStatus(str, Enum):
    PASS = "pass"
    FINDING = "finding"
    NEEDS_REVIEW = "needs_review"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    NOT_RUN = "not_run"


class Engine(str, Enum):
    CUSTOM = "custom"      # blindspot's own rule engine
    MOBSF = "mobsf"        # mobsfscan static analysis
    AI = "ai"              # local Ollama review


# ---------------------------------------------------------------------------
# Evidence and manifest structures
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """One concrete piece of evidence backing a result.

    file_path is relative to the scan workspace (or the APK-internal path).
    line numbers are 1-based and MUST be real: never fabricate them. For
    artifacts without lines (manifest attributes, binary files) leave the
    line fields None and put the artifact location in file_path.
    """
    file_path: str
    snippet: str = ""
    description: str = ""
    line_start: Optional[int] = None
    line_end: Optional[int] = None


@dataclass
class Permission:
    name: str
    protection_level: str = "unknown"  # normal|dangerous|signature|signatureOrSystem|unknown


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[dict[str, str]] = field(default_factory=list)  # scheme/host/path dicts


@dataclass
class Component:
    kind: str  # activity | service | receiver | provider
    name: str
    exported: bool = False
    permission: Optional[str] = None
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    grant_uri_permissions: bool = False
    authorities: Optional[str] = None
    intent_filters: list[IntentFilter] = field(default_factory=list)


@dataclass
class CustomPermission:
    name: str
    protection_level: str = "unknown"


@dataclass
class ManifestData:
    package: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    max_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    backup_rules: Optional[str] = None
    full_backup_content: Optional[str] = None
    data_extraction_rules: Optional[str] = None
    permissions: list[Permission] = field(default_factory=list)
    custom_permissions: list[CustomPermission] = field(default_factory=list)
    activities: list[Component] = field(default_factory=list)
    services: list[Component] = field(default_factory=list)
    receivers: list[Component] = field(default_factory=list)
    providers: list[Component] = field(default_factory=list)
    raw_xml: str = ""  # decoded manifest text when available


@dataclass
class ApkInfo:
    sha256: str = ""
    file_size: int = 0
    file_name: str = ""
    dex_count: int = 0
    native_libs: list[str] = field(default_factory=list)
    cert_sha256: list[str] = field(default_factory=list)
    cert_subjects: list[str] = field(default_factory=list)
    is_debug_signed: Optional[bool] = None


# ---------------------------------------------------------------------------
# Scan context handed to every rule
# ---------------------------------------------------------------------------

@dataclass
class ScanContext:
    scan_id: str
    workdir: Path                 # isolated per-scan workspace
    apk_path: Path                # the uploaded APK on disk
    apk: ApkInfo = field(default_factory=ApkInfo)
    manifest: Optional[ManifestData] = None
    manifest_xml_path: Optional[Path] = None
    java_roots: list[Path] = field(default_factory=list)  # jadx output / fixture sources
    smali_dir: Optional[Path] = None
    res_dir: Optional[Path] = None
    assets_dir: Optional[Path] = None
    lib_dir: Optional[Path] = None
    dex_files: list[Path] = field(default_factory=list)
    apk_entries: list[str] = field(default_factory=list)  # relative paths inside the APK
    tools: dict[str, bool] = field(default_factory=dict)  # jadx/apktool/mobsfscan/...
    config: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)        # limitations, e.g. tool missing


# ---------------------------------------------------------------------------
# Rule results
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    rule_id: str
    status: RuleStatus
    title: str = ""
    severity: Optional[Severity] = None
    confidence: Optional[Confidence] = None
    summary: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    remediation: str = ""
    owasp: list[str] = field(default_factory=list)   # e.g. ["M8"]
    cwe: list[str] = field(default_factory=list)    # e.g. ["CWE-312"]
    masvs: list[str] = field(default_factory=list)  # verified category codes only
    references: list[str] = field(default_factory=list)
    engine: Engine = Engine.CUSTOM
    rule_version: str = "1.0.0"
    duration_ms: float = 0.0
    error: Optional[str] = None
    severity_rationale: str = ""
    confidence_rationale: str = ""


# ---------------------------------------------------------------------------
# Rule base class
# ---------------------------------------------------------------------------

class Rule:
    """Base class for every detection rule.

    Subclasses set the class attributes and implement check(). The run()
    wrapper handles applies(), timing and exception capture so a crashing
    rule can never take down a scan.
    """

    id: str = "BS-XXX"
    version: str = "1.0.0"
    title: str = ""
    description: str = ""
    rationale: str = ""
    category: str = ""  # manifest|storage|network|crypto|webview|auth|platform
    default_severity: Severity = Severity.MEDIUM
    owasp: list[str] = []
    cwe: list[str] = []
    masvs: list[str] = []  # only verified MASVS category codes, e.g. MSTG-STORAGE
    remediation: str = ""
    references: list[str] = []
    enabled_by_default: bool = True

    # -- override points ----------------------------------------------------
    def applies(self, ctx: ScanContext) -> bool:
        """Return False when the rule cannot apply to this scan (missing
        artifact, e.g. no manifest or no decompiled sources)."""
        return True

    def check(self, ctx: ScanContext) -> RuleResult:
        raise NotImplementedError

    # -- framework wrapper (do not override) --------------------------------
    def run(self, ctx: ScanContext) -> RuleResult:
        started = time.perf_counter()
        try:
            if not self.applies(ctx):
                return RuleResult(
                    rule_id=self.id, status=RuleStatus.NOT_APPLICABLE,
                    title=self.title, engine=Engine.CUSTOM,
                    rule_version=self.version,
                    duration_ms=(time.perf_counter() - started) * 1000.0,
                )
            result = self.check(ctx)
            result.rule_id = self.id
            result.rule_version = self.version
            result.engine = Engine.CUSTOM
            if not result.title:
                result.title = self.title
            if not result.owasp:
                result.owasp = list(self.owasp)
            if not result.cwe:
                result.cwe = list(self.cwe)
            if not result.masvs:
                result.masvs = list(self.masvs)
            if not result.remediation:
                result.remediation = self.remediation
            if not result.references:
                result.references = list(self.references)
            if result.status == RuleStatus.FINDING and result.severity is None:
                result.severity = self.default_severity
            result.duration_ms = (time.perf_counter() - started) * 1000.0
            return result
        except Exception as exc:  # noqa: BLE001 - a rule must never kill a scan
            return RuleResult(
                rule_id=self.id, status=RuleStatus.ERROR, title=self.title,
                engine=Engine.CUSTOM, rule_version=self.version,
                error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}",
                duration_ms=(time.perf_counter() - started) * 1000.0,
            )


# ---------------------------------------------------------------------------
# Result builders
# ---------------------------------------------------------------------------

def _base(rule: Rule, status: RuleStatus) -> RuleResult:
    return RuleResult(rule_id=rule.id, status=status, title=rule.title)


def pass_result(rule: Rule, summary: str = "") -> RuleResult:
    r = _base(rule, RuleStatus.PASS)
    r.summary = summary
    return r


def finding(
    rule: Rule,
    summary: str,
    evidence: Optional[list[Evidence]] = None,
    severity: Optional[Severity] = None,
    confidence: Confidence = Confidence.HIGH,
    severity_rationale: str = "",
    confidence_rationale: str = "",
) -> RuleResult:
    r = _base(rule, RuleStatus.FINDING)
    r.summary = summary
    r.evidence = evidence or []
    r.severity = severity or rule.default_severity
    r.confidence = confidence
    r.severity_rationale = severity_rationale
    r.confidence_rationale = confidence_rationale
    return r


def needs_review(
    rule: Rule,
    summary: str,
    evidence: Optional[list[Evidence]] = None,
    severity: Optional[Severity] = None,
    confidence: Confidence = Confidence.LOW,
    severity_rationale: str = "",
    confidence_rationale: str = "",
) -> RuleResult:
    r = finding(rule, summary, evidence, severity, confidence,
                severity_rationale, confidence_rationale)
    r.status = RuleStatus.NEEDS_REVIEW
    return r


def not_applicable(rule: Rule, reason: str = "") -> RuleResult:
    r = _base(rule, RuleStatus.NOT_APPLICABLE)
    r.summary = reason
    return r
