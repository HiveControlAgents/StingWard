"""HTTP com cache em disco. Só biblioteca padrão."""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__

UA = f"stingward/{__version__} (+https://github.com/HiveControlAgents/StingWard)"


def cache_dir() -> Path:
    base = os.environ.get("STINGWARD_CACHE") or os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"), "stingward")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


class NetError(Exception):
    pass


def fetch_json(url: str, body=None, ttl: int = 0, timeout: int = 30, headers=None):
    """GET (ou POST com body) que devolve JSON. ttl > 0 usa cache em disco."""
    path = None
    if ttl:
        key = hashlib.sha256((url + json.dumps(body, sort_keys=True)).encode()).hexdigest()[:32]
        path = cache_dir() / f"{key}.json"
        try:
            if time.time() - path.stat().st_mtime < ttl:
                return json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            pass
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out = json.loads(r.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as e:
            last = e
            if e.code not in (429, 500, 502, 503, 504):
                raise NetError(f"{url}: HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            last = e
        time.sleep(1.5 * (attempt + 1))
    else:
        raise NetError(f"{url}: {last}")
    if path is not None:
        try:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(out), "utf-8")
            tmp.replace(path)
        except OSError:
            pass
    return out
