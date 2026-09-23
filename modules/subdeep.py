from __future__ import annotations

import json
import re
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from .utils import log, require_or_skip, run_cmd, unique_lines

UA = (
    "PenCentral-SubDeep/1.0 (+authorized-recon; "
    "https://local.pencentral)"
)
TIMEOUT = 18
MAX_BYTES = 2_000_000
CTX = ssl.create_default_context()

HOST_RE = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
)
JS_URL_RE = re.compile(
    r"""(?:src|href|url)\s*[=:(]\s*['"]([^'"]+\.js(?:\?[^'"]*)?)['"]""",
    re.I,
)
ABS_JS_RE = re.compile(
    r"""['"`](https?://[^'"`\s]+?\.js(?:\?[^'"`\s]*)?)['"`]""",
    re.I,
)
MAP_RE = re.compile(r"sourceMappingURL\s*=\s*(\S+)")

SEED_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/manifest.json",
    "/asset-manifest.json",
    "/package.json",
]


def _http_get(url: str, accept: str = "*/*") -> tuple[int, str, dict[str, str]]:
    req = Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": accept,
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=TIMEOUT, context=CTX) as resp:
            raw = resp.read(MAX_BYTES)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            charset = "utf-8"
            ctype = headers.get("content-type", "")
            if "charset=" in ctype:
                charset = ctype.split("charset=", 1)[-1].split(";")[0].strip() or "utf-8"
            text = raw.decode(charset, errors="ignore")
            return int(getattr(resp, "status", 200)), text, headers
    except HTTPError as e:
        try:
            body = e.read(65536).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return int(e.code), body, {}
    except (URLError, TimeoutError, ssl.SSLError, socket.timeout, OSError):
        return 0, "", {}


def normalize(name: str, root: str) -> str | None:
    host = name.strip().lower().rstrip(".")
    host = host.removeprefix("*.")
    host = host.split(":")[0]
    host = host.split("/")[0]
    if host.startswith("www."):
        # www saxla — o da subdomaindir
        pass
    if not host or " " in host or ".." in host:
        return None
    if not HOST_RE.fullmatch(host):
        return None
    root = root.lower().rstrip(".")
    if host != root and not host.endswith("." + root):
        return None
    labels = host.split(".")
    if any(not lbl or len(lbl) > 63 for lbl in labels):
        return None
    return host


class _TagParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.attrs_blob = ""

    def handle_starttag(self, tag, attrs):
        ad = {k: v or "" for k, v in attrs}
        self.attrs_blob += " ".join(ad.values()) + " "
        if tag == "script" and ad.get("src"):
            self.scripts.append(ad["src"])
        if tag in {"link", "a", "iframe", "form", "img"}:
            for key in ("href", "src", "action"):
                if ad.get(key):
                    self.links.append(ad[key])


class SubDeep:
    def __init__(self, domain: str, on_log: Callable[[str, str], None] | None = None):
        self.domain = domain.lower().rstrip(".")
        self._hits: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        self.on_log = on_log or (lambda lvl, msg: log(msg, lvl))
        self.add(self.domain, "seed")

    def add(self, host: str, source: str) -> None:
        clean = normalize(host, self.domain)
        if not clean:
            return
        with self._lock:
            self._hits.setdefault(clean, set()).add(source)

    def add_text(self, text: str, source: str) -> int:
        before = len(self._hits)
        for m in HOST_RE.findall(text or ""):
            self.add(m, source)
        # api_host = "foo.bar.domain.com" kimi parçalanmış stringlər
        patterned = re.findall(
            rf"[A-Za-z0-9._-]+\.{re.escape(self.domain)}",
            text or "",
            flags=re.I,
        )
        for m in patterned:
            self.add(m, source)
        return max(0, len(self._hits) - before)

    def hosts(self) -> list[str]:
        return sorted(self._hits)

    def dump(self) -> list[dict]:
        return [
            {"host": h, "sources": sorted(src)}
            for h, src in sorted(self._hits.items())
        ]

    def _note(self, msg: str, level: str = "info") -> None:
        self.on_log(level, msg)

    # ----- passive sources -----
    def src_crtsh(self) -> None:
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        code, body, _ = _http_get(url, accept="application/json")
        if code != 200 or not body:
            self._note("crt.sh cavab vermədi", "warn")
            return
        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            self._note("crt.sh JSON parse olunmadı", "warn")
            return
        n = 0
        for row in rows if isinstance(rows, list) else []:
            for field in ("name_value", "common_name"):
                val = row.get(field) or ""
                for part in str(val).splitlines():
                    self.add(part, "crt.sh")
                    n += 1
        self._note(f"crt.sh işləndi ({n} sətir)", "ok")

    def src_certspotter(self) -> None:
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={self.domain}&include_subdomains=true&expand=dns_names"
        )
        code, body, _ = _http_get(url, accept="application/json")
        if code != 200:
            self._note("certspotter skip", "warn")
            return
        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            return
        for row in rows if isinstance(rows, list) else []:
            for name in row.get("dns_names") or []:
                self.add(name, "certspotter")
        self._note("certspotter işləndi", "ok")

    def src_otx(self) -> None:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        code, body, _ = _http_get(url, accept="application/json")
        if code != 200:
            self._note("OTX skip", "warn")
            return
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return
        for row in data.get("passive_dns") or []:
            self.add(str(row.get("hostname") or ""), "otx")
        self._note("OTX işləndi", "ok")

    def src_urlscan(self) -> None:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=100"
        code, body, _ = _http_get(url, accept="application/json")
        if code != 200:
            self._note("urlscan skip", "warn")
            return
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return
        for row in data.get("results") or []:
            page = row.get("page") or {}
            task = row.get("task") or {}
            for val in (page.get("domain"), page.get("url"), task.get("domain"), task.get("url")):
                if not val:
                    continue
                host = urlparse(val).hostname if "://" in str(val) else str(val)
                self.add(host or "", "urlscan")
        self._note("urlscan işləndi", "ok")

    def src_hackertarget(self) -> None:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        code, body, _ = _http_get(url)
        if code != 200 or "error" in body.lower():
            self._note("hackertarget skip", "warn")
            return
        for line in body.splitlines():
            host = line.split(",")[0].strip()
            self.add(host, "hackertarget")
        self._note("hackertarget işləndi", "ok")

    def src_jldc(self) -> None:
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        code, body, _ = _http_get(url, accept="application/json")
        if code != 200:
            self._note("jldc/anubis skip", "warn")
            return
        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            return
        for host in rows if isinstance(rows, list) else []:
            self.add(str(host), "jldc")
        self._note("jldc işləndi", "ok")

    def src_threatminer(self) -> None:
        url = f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5"
        code, body, _ = _http_get(url, accept="application/json")
        if code != 200:
            return
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return
        for host in data.get("results") or []:
            self.add(str(host), "threatminer")
        self._note("threatminer işləndi", "ok")

    def src_wayback(self) -> list[str]:
        """Arxiv URL-lərindən host + JS siyahısı."""
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey&limit=2000"
        )
        code, body, _ = _http_get(url)
        js_urls: list[str] = []
        if code != 200 or not body:
            self._note("wayback skip", "warn")
            return js_urls
        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            # bəzən plain text gəlir
            rows = [[line] for line in body.splitlines() if line.startswith("http")]
        for row in rows[1:] if rows and isinstance(rows[0], list) else rows:
            original = row[0] if isinstance(row, list) else str(row)
            parsed = urlparse(original)
            if parsed.hostname:
                self.add(parsed.hostname, "wayback")
            if parsed.path.lower().endswith(".js"):
                js_urls.append(original)
        self._note(f"wayback: {len(js_urls)} js namizəd", "ok")
        return js_urls

    def src_local_tools(self) -> None:
        subfinder = require_or_skip("subfinder")
        if subfinder:
            proc = run_cmd([subfinder, "-d", self.domain, "-silent", "-all"], timeout=420)
            for line in (proc.stdout or "").splitlines():
                self.add(line, "subfinder")
        assetfinder = require_or_skip("assetfinder")
        if assetfinder:
            proc = run_cmd([assetfinder, "--subs-only", self.domain], timeout=240)
            for line in (proc.stdout or "").splitlines():
                self.add(line, "assetfinder")

    # ----- source / JS crawl -----
    def crawl_source(self, extra_js: list[str] | None = None, max_js: int = 40) -> None:
        seeds = [
            f"https://{self.domain}",
            f"https://www.{self.domain}",
            f"http://{self.domain}",
        ]
        js_queue: list[str] = []
        seen_js: set[str] = set()

        for base in seeds:
            for path in SEED_PATHS:
                url = urljoin(base, path)
                code, body, headers = _http_get(url)
                if code == 0 or not body:
                    continue
                self.add_text(body, f"source:{urlparse(url).path or '/'}")
                self.add_text(" ".join(headers.values()), "headers")
                parser = _TagParser()
                try:
                    parser.feed(body)
                except Exception:
                    pass
                self.add_text(parser.attrs_blob, "html-attr")
                page_host = urlparse(url).hostname or self.domain
                origin = f"{urlparse(url).scheme}://{page_host}"
                for src in parser.scripts:
                    absu = urljoin(origin, src)
                    if absu not in seen_js:
                        seen_js.add(absu)
                        js_queue.append(absu)
                for href in parser.links:
                    host = urlparse(urljoin(origin, href)).hostname
                    if host:
                        self.add(host, "html-link")
                for m in JS_URL_RE.findall(body):
                    absu = urljoin(origin, m)
                    if absu not in seen_js:
                        seen_js.add(absu)
                        js_queue.append(absu)

        for extra in extra_js or []:
            if extra not in seen_js:
                seen_js.add(extra)
                js_queue.append(extra)

        # eyni path-i çox arxiv snapshot-undan götürmə
        slim: list[str] = []
        seen_path: set[str] = set()
        for u in js_queue:
            key = urlparse(u)._replace(query="", fragment="").geturl()
            if key in seen_path:
                continue
            seen_path.add(key)
            slim.append(u)
        slim = slim[:max_js]
        self._note(f"JS/source fayl: {len(slim)}", "step")

        def _one(u: str) -> None:
            code, body, _ = _http_get(u)
            if code == 0 or not body:
                return
            src_name = "js" if u.lower().split("?")[0].endswith(".js") else "source"
            self.add_text(body, src_name)
            parsed = urlparse(u)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for m in ABS_JS_RE.findall(body):
                self.add(urlparse(m).hostname or "", "js-url")
            for m in MAP_RE.findall(body):
                map_url = urljoin(origin + parsed.path.rsplit("/", 1)[0] + "/", m.strip())
                self._read_sourcemap(map_url)
            if not u.endswith(".map"):
                self._read_sourcemap(u.split("?")[0] + ".map")

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(_one, slim))
        self._note("source/JS analiz bitdi", "ok")

    def _read_sourcemap(self, url: str) -> None:
        code, body, _ = _http_get(url, accept="application/json")
        if code != 200 or not body:
            return
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.add_text(body, "sourcemap")
            return
        for key in ("sources", "sourcesContent", "file"):
            val = data.get(key)
            if isinstance(val, list):
                for item in val:
                    self.add_text(str(item or ""), "sourcemap")
            elif val:
                self.add_text(str(val), "sourcemap")
        self._note(f"sourcemap oxundu: {urlparse(url).path}", "ok")

    def mutate(self) -> None:
        """Tapılan tokenlərdən kiçik, məqsədli permutasiya."""
        prefixes = {
            "www", "api", "dev", "test", "stage", "staging", "prod", "uat",
            "admin", "portal", "app", "cdn", "static", "img", "images",
            "mail", "vpn", "git", "gitlab", "grafana", "status", "docs",
            "beta", "internal", "intranet", "old", "new", "v1", "v2",
        }
        found_left = set()
        for host in list(self._hits):
            if host == self.domain:
                continue
            left = host[: -len(self.domain)].rstrip(".")
            for part in left.split("."):
                if part and part not in {"www"}:
                    found_left.add(part)
                    prefixes.add(part)
        for p in sorted(prefixes):
            self.add(f"{p}.{self.domain}", "mutate")
            self.add(f"{p}-api.{self.domain}", "mutate")
        # iki token: dev-api, staging-www yox — yalnız tapılan + api/dev
        for token in list(found_left)[:40]:
            self.add(f"dev-{token}.{self.domain}", "mutate")
            self.add(f"{token}-dev.{self.domain}", "mutate")
        self._note(f"permutasiya sonrası: {len(self._hits)} ad", "ok")

    def resolve(self, workers: int = 40) -> dict[str, list[str]]:
        resolved: dict[str, list[str]] = {}

        def _res(host: str) -> tuple[str, list[str]]:
            try:
                infos = socket.getaddrinfo(host, None)
                ips = sorted({i[4][0] for i in infos})
                return host, ips
            except socket.gaierror:
                return host, []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_res, h) for h in self.hosts()]
            for fut in as_completed(futs):
                host, ips = fut.result()
                if ips:
                    resolved[host] = ips
        self._note(f"resolve: {len(resolved)}/{len(self._hits)} canlı DNS", "ok")
        return resolved


def run_subdeep(
    domain: str,
    outdir: Path,
    *,
    crawl: bool = True,
    mutate: bool = False,
    resolve: bool = False,
    use_local_tools: bool = True,
    max_js: int = 40,
) -> Path:
    engine = SubDeep(domain)
    engine._note(f"SubDeep start: {domain}", "step")

    passive = [
        engine.src_crtsh,
        engine.src_certspotter,
        engine.src_otx,
        engine.src_urlscan,
        engine.src_hackertarget,
        engine.src_jldc,
        engine.src_threatminer,
    ]
    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = [pool.submit(fn) for fn in passive]
        for fut in as_completed(futs):
            try:
                fut.result()
            except Exception as exc:
                engine._note(f"mənbə xətası: {exc}", "warn")

    wayback_js = []
    try:
        wayback_js = engine.src_wayback()
    except Exception as exc:
        engine._note(f"wayback xəta: {exc}", "warn")

    if use_local_tools:
        engine.src_local_tools()

    if crawl:
        engine.crawl_source(extra_js=wayback_js[:25], max_js=max_js)

    if mutate:
        engine.mutate()

    resolved = engine.resolve() if resolve else {}

    outdir.mkdir(parents=True, exist_ok=True)
    hosts_path = outdir / "subdomains.txt"
    hosts_path.write_text("\n".join(engine.hosts()) + "\n", encoding="utf-8")
    (outdir / "subdomains_by_source.json").write_text(
        json.dumps(engine.dump(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    if resolved:
        lines = [f"{h} {','.join(ips)}" for h, ips in sorted(resolved.items())]
        (outdir / "subdomains_resolved.txt").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
    engine._note(f"Cəmi unikal subdomain: {len(engine.hosts())}", "ok")
    return hosts_path
