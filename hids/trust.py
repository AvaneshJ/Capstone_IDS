"""
Program trust for host alerts: the user's allow rules plus code-signing reputation.

Follows how EDR products handle false positives:
  * Allow rules are as narrow as possible. A file rule matches one exact binary (SHA-256);
    a publisher rule matches anything carrying that publisher's *valid* Authenticode signature
    (survives updates). There are no folder rules: a writable folder is where malware hides.
  * Allowed programs are still seen; their alerts are suppressed and counted.
  * Reputation: a validly signed binary inside a protected install folder (Windows /
    Program Files, admin-only) is a "trusted vendor". It is still reported, but at low risk
    and never stopped automatically. Unsigned or user-folder binaries keep full severity.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

ALLOWED = "allowed"
TRUSTED_VENDOR = "trusted_vendor"
UNVERIFIED = "unverified"
RULE_KINDS = ("hash", "publisher")

# Signed, admin-installed programs that run whatever code they are handed ("living off the land").
# Their signature says nothing about what they are doing, so they never earn trust.
CODE_RUNNERS = frozenset({
    "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "cmstp.exe",
    "wmic.exe", "forfiles.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "conhost.exe", "dllhost.exe",
    "python.exe", "pythonw.exe", "py.exe", "node.exe", "java.exe", "javaw.exe", "wsl.exe", "bash.exe",
    "ruby.exe", "perl.exe", "php.exe", "autoit3.exe", "electron.exe",
})
# Publishers that sign the operating system itself, including every code runner above.
PLATFORM_PUBLISHERS = frozenset({"microsoft windows", "microsoft windows publisher", "microsoft corporation"})


def is_code_runner(exe_path: str) -> bool:
    return os.path.basename(exe_path or "").lower() in CODE_RUNNERS


def publisher_trustable(publisher: str) -> bool:
    return bool(publisher) and publisher.strip().lower() not in PLATFORM_PUBLISHERS


@dataclass(frozen=True)
class Signature:
    status: str  # valid | unsigned | invalid | unknown
    publisher: str = ""
    thumbprint: str = ""


@dataclass(frozen=True)
class Verdict:
    level: str  # allowed | trusted_vendor | unverified
    reason: str
    publisher: str = ""
    signature: str = "unknown"
    sha256: str = ""
    rule_id: Optional[int] = None
    protected_folder: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _protected_dirs() -> Tuple[str, ...]:
    names = ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")
    return tuple({os.path.normcase(os.path.abspath(os.environ[n])) + os.sep for n in names if os.environ.get(n)})


PROTECTED_DIRS = _protected_dirs()


def in_protected_folder(exe_path: str) -> bool:
    """Windows / Program Files: only administrators can write there."""
    if not exe_path:
        return False
    return os.path.normcase(os.path.abspath(exe_path)).startswith(PROTECTED_DIRS)


_lock = threading.Lock()
_sig_cache: Dict[Tuple[str, int, int], Signature] = {}
_hash_cache: Dict[Tuple[str, int, int], str] = {}


def _stamp(path: str) -> Optional[Tuple[str, int, int]]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return os.path.normcase(os.path.abspath(path)), st.st_size, st.st_mtime_ns


_PS_SIGNATURE = (
    "$s = Get-AuthenticodeSignature -LiteralPath $env:SENTINEL_SIG_PATH; "
    "$c = $s.SignerCertificate; "
    "[pscustomobject]@{ status = [string]$s.Status; "
    "publisher = $(if ($c) { $c.GetNameInfo('SimpleName', $false) } else { '' }); "
    "thumbprint = $(if ($c) { $c.Thumbprint } else { '' }) } | ConvertTo-Json -Compress"
)


def _query_signature(path: str) -> Signature:
    if os.name != "nt":
        return Signature("unknown")
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_SIGNATURE],
            capture_output=True, text=True, timeout=20,
            env={**os.environ, "SENTINEL_SIG_PATH": path},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        data = json.loads(result.stdout.strip() or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return Signature("unknown")
    status = str(data.get("status") or "").lower()
    mapped = {"valid": "valid", "notsigned": "unsigned"}.get(status, "invalid" if status else "unknown")
    return Signature(mapped, str(data.get("publisher") or ""), str(data.get("thumbprint") or ""))


def signature(exe_path: str) -> Signature:
    """Authenticode signature of a file, cached until the file changes."""
    stamp = _stamp(exe_path) if exe_path else None
    if stamp is None:
        return Signature("unknown")
    with _lock:
        cached = _sig_cache.get(stamp)
    if cached is not None:
        return cached
    sig = _query_signature(stamp[0])
    with _lock:
        _sig_cache[stamp] = sig
    return sig


def file_sha256(exe_path: str) -> str:
    stamp = _stamp(exe_path) if exe_path else None
    if stamp is None:
        return ""
    with _lock:
        cached = _hash_cache.get(stamp)
    if cached is not None:
        return cached
    h = hashlib.sha256()
    try:
        with open(stamp[0], "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    digest = h.hexdigest()
    with _lock:
        _hash_cache[stamp] = digest
    return digest


def evaluate(exe_path: str, rules: Iterable[Mapping[str, Any]] = (), check_signature: bool = True) -> Verdict:
    """Trust level of the binary at exe_path given the user's allow rules."""
    rules = list(rules)
    protected = in_protected_folder(exe_path)
    if is_code_runner(exe_path):
        return Verdict(UNVERIFIED, f"{os.path.basename(exe_path)} runs scripts or other programs' code, "
                       "so its signature can't vouch for what it was doing.", protected_folder=protected)
    digest = file_sha256(exe_path) if any(r.get("kind") == "hash" for r in rules) else ""
    for rule in rules:
        if rule.get("kind") == "hash" and digest and digest == str(rule.get("value", "")).lower():
            return Verdict(ALLOWED, "You marked this exact program as safe.", sha256=digest,
                           rule_id=rule.get("id"), protected_folder=protected)

    sig = signature(exe_path) if (check_signature or any(r.get("kind") == "publisher" for r in rules)) else Signature("unknown")
    if sig.status == "valid":
        for rule in rules:
            if (rule.get("kind") == "publisher" and publisher_trustable(sig.publisher)
                    and sig.publisher.lower() == str(rule.get("value", "")).lower()):
                return Verdict(ALLOWED, f"You trust programs signed by {sig.publisher}.", sig.publisher, sig.status,
                               digest, rule.get("id"), protected)
        if protected:
            return Verdict(TRUSTED_VENDOR, f"Signed by {sig.publisher} and installed in a protected folder.",
                           sig.publisher, sig.status, digest, None, protected)
        return Verdict(UNVERIFIED, f"Signed by {sig.publisher}, but running from a folder any program can write to.",
                       sig.publisher, sig.status, digest, None, protected)
    reason = {"unsigned": "Not digitally signed.", "invalid": "Its digital signature is not valid."}.get(
        sig.status, "Its publisher could not be verified.")
    return Verdict(UNVERIFIED, reason, sig.publisher, sig.status, digest, None, protected)


def rule_for(exe_path: str, scope: str = "auto") -> Tuple[Optional[Dict[str, str]], str]:
    """
    Allow rule for a binary, or (None, why not).
    scope: publisher (valid signature required, not the OS publisher), file (SHA-256),
           auto (publisher when that is allowed, else file).
    """
    name = os.path.basename(exe_path)
    if is_code_runner(exe_path):
        return None, (f"{name} runs scripts and other programs' code. Trusting it would also trust anything it runs, "
                      "including malware, so it can't be marked as safe.")
    if scope in ("auto", "publisher"):
        sig = signature(exe_path)
        if sig.status == "valid" and publisher_trustable(sig.publisher):
            return {"kind": "publisher", "value": sig.publisher, "label": f"Programs signed by {sig.publisher}"}, ""
        if scope == "publisher":
            if sig.status == "valid":
                return None, f"{sig.publisher} signs Windows itself, so only this exact file can be trusted."
            return None, "This program has no valid digital signature, so only this exact file can be trusted."
    digest = file_sha256(exe_path)
    if not digest:
        return None, "The program's file couldn't be read."
    return {"kind": "hash", "value": digest, "label": f"{name} (this exact file)"}, ""
