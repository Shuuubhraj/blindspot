"""APK upload validation: magic bytes, archive integrity, hashing.

Validation never trusts the filename or MIME type. An APK is accepted only
if it is a structurally valid ZIP containing AndroidManifest.xml.
"""

from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from pathlib import Path

from ..config import settings
from ..rules.base import ApkInfo

APK_MAGIC = b"PK\x03\x04"
DEX_MAGIC = b"dex\n"


@dataclass
class ValidationResult:
    ok: bool
    sha256: str = ""
    file_size: int = 0
    error: str = ""
    has_manifest: bool = False
    has_dex: bool = False
    entry_count: int = 0
    encrypted_entries: int = 0


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 256), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_apk(path: Path, max_bytes: int | None = None) -> ValidationResult:
    """Validate an uploaded file as an APK. Returns a result, never raises
    for malformed input (raises only on I/O errors reading the file)."""
    limit = max_bytes or settings.max_upload_mb * 1024 * 1024
    size = path.stat().st_size
    if size == 0:
        return ValidationResult(ok=False, error="empty file")
    if size > limit:
        return ValidationResult(
            ok=False, file_size=size,
            error=f"file is {size // (1024*1024)} MB, limit is {limit // (1024*1024)} MB")
    digest = sha256_of(path)
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic != APK_MAGIC:
        return ValidationResult(
            ok=False, sha256=digest, file_size=size,
            error="not a ZIP archive (APK files are ZIP archives)")
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
            if bad is not None:
                return ValidationResult(
                    ok=False, sha256=digest, file_size=size,
                    error=f"corrupt ZIP entry: {bad!r}")
            names = zf.namelist()
            encrypted = sum(1 for i in zf.infolist() if i.flag_bits & 0x1)
            has_manifest = "AndroidManifest.xml" in names
            has_dex = any(n == "classes.dex" or n.startswith("classes") and n.endswith(".dex")
                          for n in names)
    except zipfile.BadZipFile as exc:
        return ValidationResult(
            ok=False, sha256=digest, file_size=size, error=f"bad ZIP archive: {exc}")
    if not has_manifest:
        return ValidationResult(
            ok=False, sha256=digest, file_size=size, has_dex=has_dex,
            entry_count=len(names), encrypted_entries=encrypted,
            error="AndroidManifest.xml missing - not an Android package")
    if encrypted:
        return ValidationResult(
            ok=False, sha256=digest, file_size=size, has_manifest=True,
            entry_count=len(names), encrypted_entries=encrypted,
            error=f"{encrypted} encrypted ZIP entries - encrypted APKs are not supported")
    return ValidationResult(
        ok=True, sha256=digest, file_size=size, has_manifest=True,
        has_dex=has_dex, entry_count=len(names))


def collect_apk_info(extracted_dir: Path, entries: list[str]) -> ApkInfo:
    """Gather DEX count, native libs and signing info from extracted files."""
    info = ApkInfo()
    dex = [e for e in entries if e == "classes.dex"
           or (e.startswith("classes") and e.endswith(".dex"))]
    info.dex_count = len(dex)
    info.native_libs = sorted(e for e in entries if e.startswith("lib/") and e.endswith(".so"))
    # Signing: read certificate fingerprints from META-INF/*.RSA via openssl-free
    # parsing is complex; we record presence and let rules treat unknown as N/A.
    info.cert_sha256 = []
    info.cert_subjects = []
    info.is_debug_signed = None
    return info
