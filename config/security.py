"""
SentinelAI - per-install secrets kept outside the repository.

Data folder (first match):
  SENTINEL_DATA_DIR                    explicit override (tests, service installs)
  %PROGRAMDATA%\\SentinelAI             default when writable
  %LOCALAPPDATA%\\SentinelAI            fallback for restricted accounts

Files created here (owner-only ACL on Windows, 0600 elsewhere):
  api_token          random token the API requires in X-SentinelAI-Token
  integrity.key      HMAC key that signs the integrity manifest and the evidence chain
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

TOKEN_FILE = "api_token"
KEY_FILE = "integrity.key"
TOKEN_HEADER = "X-SentinelAI-Token"


def _candidate_dirs() -> list[Path]:
    override = os.environ.get("SENTINEL_DATA_DIR", "").strip()
    if override:
        return [Path(override)]
    dirs = []
    for var in ("PROGRAMDATA", "LOCALAPPDATA"):
        if os.environ.get(var):
            dirs.append(Path(os.environ[var]) / "SentinelAI")
    dirs.append(Path.home() / ".sentinelai")
    return dirs


_dir_cache: Dict[Tuple[Path, ...], Path] = {}
_token_cache: Dict[Path, str] = {}


def data_dir() -> Path:
    candidates = tuple(_candidate_dirs())
    cached = _dir_cache.get(candidates)
    if cached is not None and cached.is_dir():
        return cached
    last_error: Optional[OSError] = None
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            _dir_cache[candidates] = path
            return path
        except OSError as exc:
            last_error = exc
    raise RuntimeError(f"No writable SentinelAI data folder: {last_error}")


def restrict_acl(path: Path) -> bool:
    """Owner + SYSTEM + Administrators only. Best effort; returns False if it could not be applied."""
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
            return True
        except OSError:
            return False
    user = os.environ.get("USERNAME", "")
    domain = os.environ.get("USERDOMAIN", "")
    grants = ["*S-1-5-18:F", "*S-1-5-32-544:F"]
    if user:
        grants.append(f"{domain}\\{user}:F" if domain else f"{user}:F")
    cmd = ["icacls", str(path), "/inheritance:r"]
    for grant in grants:
        cmd += ["/grant:r", grant]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _read_or_create(name: str, factory) -> str:
    path = data_dir() / name
    try:
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    except FileNotFoundError:
        pass
    value = factory()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(value, encoding="utf-8")
    os.replace(tmp, path)
    restrict_acl(path)
    return value


def api_token() -> str:
    env = os.environ.get("SENTINEL_API_TOKEN", "").strip()
    if env:
        return env
    path = token_path()
    if path not in _token_cache:
        _token_cache[path] = _read_or_create(TOKEN_FILE, lambda: secrets.token_urlsafe(32))
    return _token_cache[path]


def token_path() -> Path:
    return data_dir() / TOKEN_FILE


def integrity_key() -> bytes:
    return bytes.fromhex(_read_or_create(KEY_FILE, lambda: secrets.token_hex(32)))


def sign(data: bytes, key: Optional[bytes] = None) -> str:
    return hmac.new(key or integrity_key(), data, hashlib.sha256).hexdigest()


def tokens_equal(a: Optional[str], b: str) -> bool:
    return bool(a) and hmac.compare_digest(str(a).encode(), b.encode())
