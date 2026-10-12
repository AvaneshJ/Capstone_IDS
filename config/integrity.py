"""
SentinelAI - integrity manifest for models, policies and code.

The manifest (SHA-256 of every covered file) lives in the data folder next to the HMAC
key that signs it (config/security.py), outside the repository. Model files are hashed
from the same bytes that are unpickled, so a swapped .pkl/.joblib is never deserialised.

  python -m config.integrity generate     trust the files as they are now
  python -m config.integrity verify       compare the install against the manifest
  python -m config.integrity show         print where the manifest and key live

SENTINEL_INTEGRITY_REQUIRED=1 refuses to load models when no manifest exists.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import os
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import security
from config.paths import MODELS_DIR, ROOT

logger = logging.getLogger("SentinelAI.Integrity")

MANIFEST_FILE = "integrity_manifest.json"
COVERED = (
    "models/*.pkl",
    "models/*.joblib",
    "soar/rules/*.yaml",
    "soar/database/schema.sql",
    "config/*.py",
    "soar/**/*.py",
    "hids/**/*.py",
    "nids/**/*.py",
    "dashboard/electron/*.cjs",
)
EXCLUDED_DIRS = {"tests", "__pycache__", "logs", "manifests", "reports", "node_modules"}
CHUNK = 1 << 20


class IntegrityError(RuntimeError):
    pass


@dataclass
class IntegrityReport:
    state: str  # ok | tampered | bad_signature | no_manifest
    checked_at: float = field(default_factory=time.time)
    files_checked: int = 0
    modified: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    manifest_created_at: Optional[float] = None

    @property
    def problems(self) -> List[str]:
        return self.modified + self.missing + self.added

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_path() -> Path:
    return security.data_dir() / MANIFEST_FILE


def rel(path: Path, root: Path = ROOT) -> Optional[str]:
    try:
        return Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root))).as_posix()
    except ValueError:
        return None


def covered_files(root: Path = ROOT, patterns: Iterable[str] = COVERED) -> List[Path]:
    found: Dict[str, Path] = {}
    for pattern in patterns:
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            parts = path.relative_to(root).parts[:-1]
            if EXCLUDED_DIRS.intersection(parts):
                continue
            found[path.relative_to(root).as_posix()] = path
    return [found[k] for k in sorted(found)]


def _canonical(files: Dict[str, str], created_at: float) -> bytes:
    return json.dumps({"created_at": created_at, "files": files}, sort_keys=True, separators=(",", ":")).encode()


def build_manifest(root: Path = ROOT, key: Optional[bytes] = None) -> Dict[str, Any]:
    files = {p.relative_to(root).as_posix(): sha256_file(p) for p in covered_files(root)}
    created_at = round(time.time(), 3)
    return {
        "version": 1,
        "created_at": created_at,
        "files": files,
        "signature": security.sign(_canonical(files, created_at), key),
    }


def write_manifest(path: Optional[Path] = None, root: Path = ROOT) -> Dict[str, Any]:
    path = path or manifest_path()
    manifest = build_manifest(root)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    security.restrict_acl(path)
    _cache.clear()
    return manifest


def load_manifest(path: Optional[Path] = None) -> Tuple[Optional[Dict[str, Any]], bool]:
    """(manifest, signature_ok). (None, False) when there is no manifest."""
    path = path or manifest_path()
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        files = manifest["files"]
        expected = security.sign(_canonical(files, manifest["created_at"]))
        return manifest, security.tokens_equal(manifest.get("signature"), expected)
    except FileNotFoundError:
        return None, False
    except (ValueError, KeyError, TypeError):
        return {"files": {}, "created_at": None}, False


class _ManifestCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key: Optional[Tuple[str, int]] = None
        self._value: Tuple[Optional[Dict[str, Any]], bool] = (None, False)

    def get(self, path: Optional[Path] = None) -> Tuple[Optional[Dict[str, Any]], bool]:
        path = Path(path or manifest_path())
        try:
            stamp = (str(path), path.stat().st_mtime_ns)
        except FileNotFoundError:
            return None, False
        with self._lock:
            if stamp != self._key:
                self._value = load_manifest(path)
                self._key = stamp
            return self._value

    def clear(self) -> None:
        with self._lock:
            self._key = None


_cache = _ManifestCache()


def _required() -> bool:
    return os.environ.get("SENTINEL_INTEGRITY_REQUIRED", "0").strip() == "1"


def check_model_bytes(path: Path, data: bytes, manifest_file: Optional[Path] = None, root: Path = ROOT) -> None:
    """Raise IntegrityError unless `data` (the bytes about to be unpickled) matches the trusted manifest."""
    manifest, signature_ok = _cache.get(manifest_file)
    rel_path = rel(path, root)
    in_models = rel(path, root / MODELS_DIR.name) is not None
    if manifest is None:
        if _required():
            raise IntegrityError(f"No integrity manifest; refusing to load {path} (SENTINEL_INTEGRITY_REQUIRED=1)")
        logger.warning("No integrity manifest; loading %s unverified. Run: python -m config.integrity generate", path)
        return
    if not signature_ok:
        raise IntegrityError(f"Integrity manifest signature is invalid; refusing to load {path}")
    expected = manifest["files"].get(rel_path) if rel_path else None
    if expected is None:
        if in_models:
            raise IntegrityError(f"{path} is not in the trusted manifest; refusing to load it")
        return
    actual = sha256_bytes(data)
    if actual != expected:
        raise IntegrityError(f"{path} was modified (sha256 {actual[:12]}... != trusted {expected[:12]}...)")


def load_verified(path: Any, manifest_file: Optional[Path] = None, root: Path = ROOT) -> Any:
    """joblib.load() that hashes the file before anything is deserialised."""
    import joblib

    path = Path(path)
    data = path.read_bytes()
    check_model_bytes(path, data, manifest_file, root)
    return joblib.load(io.BytesIO(data))


def verify(root: Path = ROOT, manifest_file: Optional[Path] = None) -> IntegrityReport:
    return IntegrityMonitor(root, manifest_file).check(full=True)


class IntegrityMonitor:
    """Re-verifies the install. Unchanged files (same size + mtime) reuse their last hash unless full=True."""

    def __init__(self, root: Path = ROOT, manifest_file: Optional[Path] = None) -> None:
        self.root = root
        self.manifest_file = manifest_file
        self._hashes: Dict[str, Tuple[Tuple[int, int], str]] = {}
        self.last: Optional[IntegrityReport] = None

    def _hash(self, key: str, path: Path, full: bool) -> Optional[str]:
        try:
            st = path.stat()
        except FileNotFoundError:
            return None
        stamp = (st.st_size, st.st_mtime_ns)
        cached = self._hashes.get(key)
        if cached and cached[0] == stamp and not full:
            return cached[1]
        digest = sha256_file(path)
        self._hashes[key] = (stamp, digest)
        return digest

    def check(self, full: bool = False) -> IntegrityReport:
        manifest, signature_ok = load_manifest(self.manifest_file)
        if manifest is None:
            self.last = IntegrityReport(state="no_manifest")
            return self.last
        trusted: Dict[str, str] = manifest.get("files", {})
        report = IntegrityReport(state="ok", manifest_created_at=manifest.get("created_at"))
        for key, expected in trusted.items():
            digest = self._hash(key, self.root / key, full)
            report.files_checked += 1
            if digest is None:
                report.missing.append(key)
            elif digest != expected:
                report.modified.append(key)
        current = {p.relative_to(self.root).as_posix() for p in covered_files(self.root)}
        report.added = sorted(current - set(trusted))
        if not signature_ok:
            report.state = "bad_signature"
        elif report.problems:
            report.state = "tampered"
        self.last = report
        return report


class AppendOnlyWatch:
    """Sensor CSV logs only ever grow. Flags files that shrink, vanish, or whose old content changes."""

    PREFIX = 64 * 1024

    def __init__(self, folder: Path, pattern: str = "*.csv") -> None:
        self.folder = folder
        self.pattern = pattern
        self._seen: Dict[str, Tuple[int, str]] = {}

    def _prefix_hash(self, path: Path, length: int) -> str:
        with open(path, "rb") as f:
            return sha256_bytes(f.read(min(length, self.PREFIX)))

    def check(self) -> List[str]:
        problems: List[str] = []
        current = {p.name: p for p in self.folder.glob(self.pattern)} if self.folder.is_dir() else {}
        for name, (size, prefix) in list(self._seen.items()):
            path = current.get(name)
            if path is None:
                problems.append(f"{name} deleted")
                del self._seen[name]
                continue
            try:
                new_size = path.stat().st_size
                if new_size < size:
                    problems.append(f"{name} truncated ({size} -> {new_size} bytes)")
                elif self._prefix_hash(path, size) != prefix:
                    problems.append(f"{name} edited")
            except OSError:
                continue
        for name, path in current.items():
            try:
                size = path.stat().st_size
                self._seen[name] = (size, self._prefix_hash(path, size))
            except OSError:
                continue
        return problems


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelAI integrity manifest")
    parser.add_argument("command", choices=("generate", "verify", "show"))
    args = parser.parse_args()

    if args.command == "generate":
        manifest = write_manifest()
        print(f"Trusted manifest written: {manifest_path()} ({len(manifest['files'])} files)")
        print("Re-run this after you intentionally update models, policies or code.")
    elif args.command == "verify":
        report = verify()
        print(f"State: {report.state} ({report.files_checked} files checked)")
        for label, items in (("MODIFIED", report.modified), ("MISSING", report.missing), ("ADDED", report.added)):
            for item in items:
                print(f"  {label:<8} {item}")
        sys.exit(0 if report.state == "ok" else 1)
    else:
        print(f"Data folder : {security.data_dir()}")
        print(f"Manifest    : {manifest_path()} ({'present' if manifest_path().exists() else 'missing'})")
        print(f"HMAC key    : {security.data_dir() / security.KEY_FILE}")
        print(f"API token   : {security.token_path()}")


if __name__ == "__main__":
    main()
