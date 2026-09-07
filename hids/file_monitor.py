"""
File / cookie-path monitor stub (watchdog).

Phase 5: watch Chrome/Discord/Steam session paths in a lab profile only.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

# Example sensitive path *patterns* (resolve per-user in Phase 5)
SENSITIVE_GLOBS = [
    "**/Google/Chrome/User Data/**/Cookies",
    "**/discord/**/Local Storage/**",
    "**/Steam/config/**",
]


def describe_watch_targets() -> List[str]:
    return list(SENSITIVE_GLOBS)


def path_looks_sensitive(path: str | Path) -> bool:
    text = str(path).lower().replace("\\", "/")
    needles = ("cookies", "login data", "local storage", "steam/config", "discord")
    return any(n in text for n in needles)


if __name__ == "__main__":
    print("HIDS file monitor stub — planned watch globs:")
    for g in describe_watch_targets():
        print(" ", g)
