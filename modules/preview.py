from __future__ import annotations

import re
import socket
import ssl
import subprocess
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from .utils import which

# Real brauzer UA — bəzi WAF/CDN "PenCentral/1.0" kimi UA-ları bloklayır və
# host canlı olsa da cavab gəlmir. Browser UA ilə false-negative azalır.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
PROBE_TIMEOUT = 12
PROBE_TRIES = 2


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirect(HTTPRedirectHandler):
    """Redirect-i izləmə — 301/302 kodun özünü görmək üçün."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _opener(ctx: ssl.SSLContext):
    return build_opener(HTTPSHandler(context=ctx), _NoRedirect)


def _status_for(url: str, opener, timeout: int = PROBE_TIMEOUT, tries: int = PROBE_TRIES) -> int | None:
    """URL-in əsl status kodunu qaytarır (200/301/403/500...). Redirect izlənmir.

    HTTP cavabı gələn hər şey (3xx/4xx/5xx daxil) "canlı" sayılır — yalnız
    şəbəkə/DNS/TLS səviyyəsində heç cavab gəlməyəndə None qayıdır.
    """
    last_err: Exception | None = None
    for _ in range(max(1, tries)):
        req = Request(
            url,
            headers={"User-Agent": BROWSER_UA, "Accept": "*/*"},
            method="GET",
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                return int(getattr(resp, "status", 200))
        except HTTPError as exc:
            # 301/302/401/403/404/500... hamısı canlı host deməkdir
            return int(exc.code)
        except (URLError, ssl.SSLError, socket.timeout, TimeoutError, OSError) as exc:
            last_err = exc
            continue
    return None


CHROME_CANDIDATES = (
    "google-chrome-stable",
    "google-chrome",
    "chromium",
    "chromium-browser",
)


def chrome_bin() -> str | None:
    for name in CHROME_CANDIDATES:
        path = which(name)
        if path:
            return path
    return None


def host_from(value: str) -> str:
    value = (value or "").strip()
    value = re.sub(r"^https?://", "", value, flags=re.I)
    return value.split("/")[0].split(":")[0].split()[0].lower()


def guess_url(value: str, fallback_domain: str = "") -> str:
    raw = (value or "").strip().split()[0]
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    host = host_from(raw) or fallback_domain
    if not host:
        return ""
    return f"https://{host}"


def resolve_ips(host: str) -> str:
    host = host_from(host)
    if not host:
        return ""
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return ", ".join(ips)
    except socket.gaierror:
        return ""


def probe_hosts(hosts: list[str], verbose_path: Path | None = None, limit: int | None = None) -> list[str]:
    """Hər host üçün canlı URL + status. `limit=None` → BÜTÜN hostlar yoxlanır.

    Əvvəlki versiya yalnız ilk 80 host-u yoxlayırdı; ondan sonrakı canlı
    subdomainlər "ölü" kimi görünürdü. İndi hamısı yoxlanır.
    """
    from concurrent.futures import ThreadPoolExecutor

    ctx = _ssl_ctx()
    opener = _opener(ctx)

    def one(host: str) -> str | None:
        name = host_from(host)
        if not name:
            return None
        for scheme in ("https", "http"):
            code = _status_for(f"{scheme}://{name}", opener)
            if code is not None:
                return f"{scheme}://{name} [{code}]"
        return None

    pool_hosts = hosts if limit is None else hosts[:limit]
    lines: list[str] = []
    with ThreadPoolExecutor(max_workers=24) as pool:
        for row in pool.map(one, pool_hosts):
            if row:
                lines.append(row)
    lines = sorted(set(lines))
    if verbose_path is not None:
        verbose_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return lines


def screenshot_url(url: str, dest: Path, timeout: int = 25) -> bool:
    chrome = chrome_bin()
    if not chrome or not url:
        return False
    dest = dest.resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    variants = [
        [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--hide-scrollbars",
            "--ignore-certificate-errors",
            "--window-size=1366,800",
            f"--screenshot={dest}",
            "--virtual-time-budget=10000",
            "--default-background-color=FFFFFFFF",
            url,
        ],
        [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--window-size=1366,800",
            f"--screenshot={dest}",
            url,
        ],
    ]
    for cmd in variants:
        try:
            subprocess.run(
                cmd,
                timeout=timeout,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except subprocess.TimeoutExpired:
            continue
        if dest.exists() and dest.stat().st_size > 500:
            return True
        fallback = Path.cwd() / "screenshot.png"
        if fallback.exists() and fallback.stat().st_size > 500:
            fallback.replace(dest)
            return dest.exists() and dest.stat().st_size > 500
    return False


def live_status(url_or_host: str) -> tuple[str, str]:
    """Qaytarır (işləyən url, status kod). Redirect izlənmir ki, 301/302 görünsün."""
    opener = _opener(_ssl_ctx())
    host = host_from(url_or_host)
    candidates: list[str] = []
    if str(url_or_host).startswith("http"):
        candidates.append(url_or_host.strip().split()[0])
    if host:
        candidates.extend([f"https://{host}", f"http://{host}"])
    seen: set[str] = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        code = _status_for(url, opener)
        if code is not None:
            return url, str(code)
    return (candidates[0] if candidates else ""), ""
