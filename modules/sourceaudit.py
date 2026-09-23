from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
import ssl

from .preview import host_from
from .utils import log, unique_lines, write_lines

UA = "PenCentral-SourceAudit/1.0"
TIMEOUT = 12
MAX_BYTES = 1_800_000
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

JS_SRC_RE = re.compile(
    r"""(?:src|href)\s*=\s*['"]([^'"]+\.js(?:\?[^'"]*)?)['"]""",
    re.I,
)
ABS_JS_RE = re.compile(
    r"""['"`](https?://[^'"`\s>]+\.js(?:\?[^'"`\s>]*)?)['"`]""",
    re.I,
)
MAP_RE = re.compile(r"sourceMappingURL\s*=\s*(\S+)")
HOST_RE = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}"
)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")

NOISE_DOMAINS = {
    "googleapis.com",
    "gstatic.com",
    "google.com",
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.com",
    "facebook.net",
    "twitter.com",
    "x.com",
    "instagram.com",
    "linkedin.com",
    "youtube.com",
    "ytimg.com",
    "cloudflare.com",
    "cloudflareinsights.com",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "jquery.com",
    "github.com",
    "githubusercontent.com",
    "w3.org",
    "schema.org",
    "sentry.io",
    "hotjar.com",
    "cookiebot.com",
    "googlesyndication.com",
    "doubleclick.net",
}

# (name, severity, regex)
RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("Google API key", "high", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    (
        "Firebase config",
        "high",
        re.compile(
            r"apiKey\s*[:=]\s*['\"]AIza[^'\"]+['\"][\s\S]{0,400}?(?:authDomain|projectId|storageBucket|messagingSenderId|appId)",
            re.I,
        ),
    ),
    ("Firebase URL", "medium", re.compile(r"[a-z0-9-]+\.firebaseio\.com", re.I)),
    ("Firebase storage", "medium", re.compile(r"[a-z0-9-]+\.appspot\.com", re.I)),
    (
        "Google OAuth client",
        "medium",
        re.compile(r"\d{10,13}-[a-z0-9]{32}\.apps\.googleusercontent\.com", re.I),
    ),
    ("AWS Access Key", "critical", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "AWS secret assignment",
        "critical",
        re.compile(
            r"(?:aws)?_?secret(?:_access)?_?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
            re.I,
        ),
    ),
    ("GitHub token", "critical", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("GitHub PAT", "critical", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("GitLab token", "high", re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("Slack token", "critical", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", "critical", re.compile(r"sk_live_[0-9a-zA-Z]{20,}")),
    ("Stripe publishable", "low", re.compile(r"pk_live_[0-9a-zA-Z]{20,}")),
    ("Twilio SID", "medium", re.compile(r"AC[a-f0-9]{32}")),
    ("Twilio auth", "high", re.compile(r"SK[a-f0-9]{32}")),
    ("SendGrid", "high", re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}")),
    ("Mailgun", "high", re.compile(r"key-[a-f0-9]{32}")),
    (
        "OpenAI key",
        "high",
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
    ),
    (
        "Supabase anon/service",
        "medium",
        re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
    ),
    ("PEM private key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "Generic API key assignment",
        "medium",
        re.compile(
            r"""(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-/.+=]{12,}['"]""",
            re.I,
        ),
    ),
    ("S3 bucket", "low", re.compile(r"[a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com", re.I)),
    (
        "Azure blob",
        "low",
        re.compile(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", re.I),
    ),
]


class _Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        ad = {k: v or "" for k, v in attrs}
        if ad.get("src"):
            self.scripts.append(ad["src"])


def _get(url: str) -> str:
    req = Request(url, headers={"User-Agent": UA, "Accept": "*/*"}, method="GET")
    try:
        with urlopen(req, timeout=TIMEOUT, context=CTX) as resp:
            return resp.read(MAX_BYTES).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _internal_ip(ip: str) -> bool:
    parts = [int(x) for x in ip.split(".")]
    a, b = parts[0], parts[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return False
    return False


def _clip(value: str, n: int = 180) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= n else value[: n - 1] + "…"


def analyze_text(text: str, source_url: str, root_domain: str) -> list[dict]:
    hits: list[dict] = []
    seen: set[str] = set()

    def add(kind: str, title: str, detail: str, severity: str) -> None:
        key = f"{kind}|{title}|{detail}"
        if key in seen:
            return
        seen.add(key)
        hits.append(
            {
                "kind": kind,
                "title": title,
                "detail": f"{detail}\n@ {source_url}",
                "severity": severity,
                "url": source_url,
            }
        )

    if not text:
        return hits

    for name, sev, rx in RULES:
        for m in rx.finditer(text):
            add("secret", name, _clip(m.group(0)), sev)

    root = root_domain.lower().rstrip(".")
    for host in HOST_RE.findall(text):
        host = host.lower().rstrip(".")
        if host.endswith(".js") or host.endswith(".css"):
            continue
        base = ".".join(host.split(".")[-2:])
        if any(host == n or host.endswith("." + n) for n in NOISE_DOMAINS):
            continue
        if host == root or host.endswith("." + root):
            add("domain", f"In-scope host: {host}", host, "info")
        elif base not in {"com", "net", "org", "io", "az", "ru"}:
            add("domain", f"External host: {host}", host, "low")

    for ip in IPV4_RE.findall(text):
        if _internal_ip(ip):
            add("ip", f"Daxili IP: {ip}", ip, "medium")

    return hits


def collect_assets(page_url: str, html: str, max_js: int = 12) -> list[str]:
    assets = [page_url]
    parsed = urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    parser = _Scripts()
    try:
        parser.feed(html)
    except Exception:
        pass
    candidates = list(parser.scripts)
    candidates += JS_SRC_RE.findall(html)
    candidates += ABS_JS_RE.findall(html)
    seen: set[str] = set()
    out: list[str] = []
    for src in candidates:
        absu = urljoin(origin + "/", src)
        if absu in seen:
            continue
        seen.add(absu)
        out.append(absu)
        if len(out) >= max_js:
            break
    return assets + out


def audit_url(page_url: str, root_domain: str, max_js: int = 12) -> list[dict]:
    html = _get(page_url)
    hits = analyze_text(html, page_url, root_domain)
    assets = collect_assets(page_url, html, max_js=max_js)[1:]
    for asset in assets:
        body = _get(asset)
        hits.extend(analyze_text(body, asset, root_domain))
        for m in MAP_RE.findall(body):
            map_url = urljoin(asset, m.strip())
            mapped = _get(map_url)
            if mapped:
                hits.extend(analyze_text(mapped, map_url, root_domain))
        map_guess = asset.split("?")[0] + ".map"
        mapped = _get(map_guess)
        if mapped:
            hits.extend(analyze_text(mapped, map_guess, root_domain))
    return hits


def run_source_audit(
    live_urls: list[str],
    root_domain: str,
    outdir: Path,
    max_hosts: int = 20,
    max_js: int = 10,
) -> Path:
    """Hər live subdomain üçün HTML+JS source analiz."""
    out = outdir / "source_audit.json"
    urls: list[str] = []
    seen_host: set[str] = set()
    for raw in live_urls:
        raw = raw.strip().split()[0]
        if not raw.startswith("http"):
            raw = "https://" + raw
        host = host_from(raw)
        if not host or host in seen_host:
            continue
        seen_host.add(host)
        urls.append(raw.rstrip("/"))
        if len(urls) >= max_hosts:
            break

    log(f"Source audit: {len(urls)} host", "step")
    all_hits: list[dict] = []

    def work(u: str) -> list[dict]:
        try:
            return audit_url(u, root_domain, max_js=max_js)
        except Exception as exc:
            log(f"source fail {u}: {exc}", "warn")
            return []

    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(work, u): u for u in urls}
        for fut in as_completed(futs):
            batch = fut.result()
            all_hits.extend(batch)
            log(f"{futs[fut]} → {len(batch)} tapıntı", "info")

    # dedup
    uniq: list[dict] = []
    bag: set[str] = set()
    for h in all_hits:
        key = h["kind"] + "|" + h["title"] + "|" + h["detail"].split("\n", 1)[0]
        if key in bag:
            continue
        bag.add(key)
        uniq.append(h)

    outdir.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(uniq, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [f"[{h['severity']}] {h['title']} :: {h['detail'].splitlines()[0]}" for h in uniq]
    write_lines(outdir / "source_audit.txt", lines)
    log(f"Source audit cəmi: {len(uniq)}", "ok")
    return out
