
from __future__ import annotations
from typing import Dict, Callable, Any

_SCANNERS: dict[str, Callable[..., Any]] = {}

def register_scanner(name: str):
    def deco(fn):
        _SCANNERS[name] = fn
        return fn
    return deco

def get_scanner(name: str):
    return _SCANNERS[name]

def list_scanners() -> list[str]:
    return sorted(_SCANNERS.keys())
