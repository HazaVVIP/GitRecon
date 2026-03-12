"""
core/http_client.py
HTTP engine: retry, proxy, SSL bypass, UA rotation, rate limiting.
Zero external dependencies.
"""

import time
import random
import socket
import urllib.request
import urllib.error
import urllib.parse
import ssl
import gzip
import zlib as _zlib
from dataclasses import dataclass, field
from typing import Optional


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


@dataclass
class HttpConfig:
    timeout:      int            = 10
    retries:      int            = 3
    delay:        float          = 0.0
    jitter:       float          = 0.0
    proxy:        Optional[str]  = None
    verify_ssl:   bool           = False
    custom_ua:    Optional[str]  = None
    extra_headers: dict          = field(default_factory=dict)
    max_size:     int            = 100 * 1024 * 1024   # 100 MB


@dataclass
class Response:
    url:        str
    status:     int
    body:       bytes
    headers:    dict
    elapsed_ms: float
    error:      Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == 200

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class HttpClient:
    def __init__(self, cfg: HttpConfig = None):
        self._cfg = cfg or HttpConfig()
        self._last_req = 0.0
        self._n_req    = 0

        self._ssl = ssl.create_default_context()
        if not self._cfg.verify_ssl:
            self._ssl.check_hostname = False
            self._ssl.verify_mode    = ssl.CERT_NONE

    # ── Public ──────────────────────────────────────

    def get(self, url: str) -> Response:
        self._rate_limit()
        last_err = None

        for attempt in range(self._cfg.retries):
            try:
                r = self._do_get(url)
                self._n_req += 1
                return r
            except urllib.error.HTTPError as e:
                return Response(url=url, status=e.code, body=b"",
                                headers={}, elapsed_ms=0, error=str(e))
            except (urllib.error.URLError, socket.timeout,
                    ConnectionResetError, OSError) as e:
                last_err = str(e)
                if attempt < self._cfg.retries - 1:
                    time.sleep(0.5 * (2 ** attempt))
            except Exception as e:
                last_err = str(e)
                break

        return Response(url=url, status=0, body=b"",
                        headers={}, elapsed_ms=0, error=last_err)

    @property
    def request_count(self) -> int:
        return self._n_req

    # ── Internal ─────────────────────────────────────

    def _do_get(self, url: str) -> Response:
        req    = self._build_req(url)
        opener = self._build_opener()
        t0     = time.time()

        with opener.open(req, timeout=self._cfg.timeout) as resp:
            elapsed = (time.time() - t0) * 1000
            body    = b""
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > self._cfg.max_size:
                    break

            enc = resp.headers.get("Content-Encoding", "")
            if enc == "gzip":
                body = gzip.decompress(body)
            elif enc == "deflate":
                body = _zlib.decompress(body)

            return Response(url=url, status=resp.status, body=body,
                            headers=dict(resp.headers), elapsed_ms=elapsed)

    def _build_req(self, url: str) -> urllib.request.Request:
        ua = self._cfg.custom_ua or random.choice(USER_AGENTS)
        h  = {
            "User-Agent":      ua,
            "Accept":          "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Cache-Control":   "no-cache",
            **self._cfg.extra_headers,
        }
        return urllib.request.Request(url, headers=h)

    def _build_opener(self):
        handlers = [urllib.request.HTTPSHandler(context=self._ssl)]
        if self._cfg.proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http": self._cfg.proxy, "https": self._cfg.proxy
            }))
        return urllib.request.build_opener(*handlers)

    def _rate_limit(self):
        if self._cfg.delay <= 0:
            return
        wait = self._cfg.delay - (time.time() - self._last_req)
        if self._cfg.jitter > 0:
            wait += random.uniform(0, self._cfg.jitter)
        if wait > 0:
            time.sleep(wait)
        self._last_req = time.time()
