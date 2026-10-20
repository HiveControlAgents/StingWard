"""HTTP com cache em disco. Só biblioteca padrão."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__

UA = f"stingward/{__version__} (+https://github.com/HiveControlAgents/StingWard)"


def cache_dir():
    """Pasta do cache, ou None se não der para criar (aí só não usa cache)."""
    base = os.environ.get("STINGWARD_CACHE") or os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache"), "stingward")
    p = Path(base)
    try:
        p.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    return p


class NetError(Exception):
    pass


def fetch_json(url: str, body=None, ttl: int = 0, timeout: int = 30, headers=None):
    """GET (ou POST com body) que devolve JSON. ttl > 0 usa cache em disco."""
    path = None
    cache = cache_dir() if ttl else None
    if cache is not None:
        key = hashlib.sha256((url + json.dumps(body, sort_keys=True)).encode()).hexdigest()[:32]
        path = cache / f"{key}.json"
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
        # URLError, timeout, conexão derrubada no meio (RemoteDisconnected, reset, IncompleteRead) ou JSON quebrado.
        except (OSError, http.client.HTTPException, ValueError) as e:
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
