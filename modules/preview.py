from __future__ import annotations

import re
import socket
import subprocess
from pathlib import Path

from .utils import which

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


def probe_hosts(hosts: list[str], verbose_path: Path | None = None, limit: int = 80) -> list[str]:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from urllib.request import Request, urlopen
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    lines: list[str] = []

    def one(host: str) -> str | None:
        name = host_from(host)
        if not name:
            return None
        for scheme in ("https", "http"):
            url = f"{scheme}://{name}"
            req = Request(url, headers={"User-Agent": "PenCentral/1.0"}, method="GET")
            try:
                with urlopen(req, timeout=8, context=ctx) as resp:
                    code = getattr(resp, "status", 200)
                    return f"{url} [{code}]"
            except Exception:
                continue
        return None

    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = [pool.submit(one, h) for h in hosts[:limit]]
        for fut in as_completed(futs):
            row = fut.result()
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
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--hide-scrollbars",
        "--ignore-certificate-errors",
        "--window-size=1366,800",
        f"--screenshot={dest}",
        "--virtual-time-budget=8000",
        url,
    ]
    try:
        subprocess.run(
            cmd,
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    return dest.exists() and dest.stat().st_size > 500
