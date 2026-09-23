#!/usr/bin/env python3
"""PenCentral UI — yalnız Python standart kitabxanası."""

from __future__ import annotations

import json
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from modules import db
from modules.preview import guess_url, host_from
from modules.runner import start_adapt, start_scan
from modules.utils import which

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "output"

STATIC = Path(__file__).resolve().parent / "static"
VALID_STAGES = {"subs", "probe", "ports", "dirs", "source", "nuclei"}
TOOLS = ["subfinder", "assetfinder", "httpx", "naabu", "nmap", "ffuf", "feroxbuster", "nuclei"]
MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
}


def json_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length") or 0)
    raw = handler.rfile.read(length) if length else b"{}"
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[http]", args[0])

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"), MIME[".json"])

    def _err(self, code: int, msg: str) -> None:
        self._json(code, {"detail": msg})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)

        if path == "/":
            self._file(STATIC / "index.html")
            return
        if path.startswith("/static/"):
            self._file(STATIC / path.removeprefix("/static/"))
            return
        if path == "/api/tools":
            self._json(200, {name: bool(which(name)) for name in TOOLS})
            return
        if path == "/api/scans":
            self._json(200, db.list_scans())
            return
        if path.startswith("/api/scans/") and path.endswith("/export.txt"):
            sid = _id_from(path, "/api/scans/", "/export.txt")
            return self._export(sid, "txt")
        if path.startswith("/api/scans/") and path.endswith("/export.csv"):
            sid = _id_from(path, "/api/scans/", "/export.csv")
            return self._export(sid, "csv")
        if path.startswith("/api/scans/") and path.endswith("/findings"):
            sid = _id_from(path, "/api/scans/", "/findings")
            if sid is None or not db.get_scan(sid):
                return self._err(404, "Scan yoxdur")
            cat = q.get("category", [None])[0] or None
            self._json(200, db.get_findings(sid, cat))
            return
        if path.startswith("/api/scans/") and path.endswith("/logs"):
            sid = _id_from(path, "/api/scans/", "/logs")
            if sid is None or not db.get_scan(sid):
                return self._err(404, "Scan yoxdur")
            after = int(q.get("after", ["0"])[0] or 0)
            self._json(200, db.get_logs(sid, after))
            return
        if path.startswith("/api/scans/"):
            sid = _id_from(path, "/api/scans/", "")
            scan = db.get_scan(sid) if sid else None
            if not scan:
                return self._err(404, "Scan yoxdur")
            scan["counts"] = db.counts_by_category(sid)
            self._json(200, scan)
            return
        self._err(404, "Not found")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            body = json_body(self)
        except json.JSONDecodeError:
            return self._err(400, "JSON düzgün deyil")

        if path == "/api/scans":
            return self._new_scan(body)
        if path == "/api/demo":
            return self._demo()
        if path.startswith("/api/findings/") and path.endswith("/review"):
            fid = _id_from(path, "/api/findings/", "/review")
            if fid is None:
                return self._err(400, "id yoxdur")
            db.set_reviewed(fid, bool(body.get("reviewed")), body.get("note"))
            return self._json(200, {"ok": True})
        if path.startswith("/api/scans/") and path.endswith("/adapt"):
            sid = _id_from(path, "/api/scans/", "/adapt")
            if sid is None or not db.get_scan(sid):
                return self._err(404, "Scan yoxdur")
            start_adapt(sid)
            return self._json(200, {"ok": True, "id": sid})
        if path.startswith("/api/findings/") and path.endswith("/notes"):
            fid = _id_from(path, "/api/findings/", "/notes")
            if fid is None:
                return self._err(400, "id yoxdur")
            text = str(body.get("text") or body.get("note") or "").strip()
            if not text:
                return self._err(400, "Qeyd boşdur")
            note = db.add_note(fid, text)
            return self._json(200, note)
        if path.startswith("/api/findings/") and path.endswith("/note"):
            fid = _id_from(path, "/api/findings/", "/note")
            if fid is None:
                return self._err(400, "id yoxdur")
            db.set_note(fid, str(body.get("note") or ""))
            return self._json(200, {"ok": True})
        self._err(404, "Not found")

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/scans/"):
            sid = _id_from(path, "/api/scans/", "")
            if sid is None or not db.get_scan(sid):
                return self._err(404, "Scan yoxdur")
            db.delete_scan(sid)
            shot_dir = ROOT / "data" / "shots" / str(sid)
            if shot_dir.exists():
                shutil.rmtree(shot_dir, ignore_errors=True)
            return self._json(200, {"ok": True})
        self._err(404, "Not found")

    def _new_scan(self, body: dict) -> None:
        if not body.get("authorized"):
            return self._err(400, "İcazə qutusunu işarələ — yalnız authorized target.")
        target = str(body.get("target") or "").strip().lower()
        target = target.removeprefix("https://").removeprefix("http://").split("/")[0]
        if not target or " " in target:
            return self._err(400, "Target düzgün deyil")
        stages = [s for s in (body.get("stages") or []) if s in VALID_STAGES]
        if not stages:
            return self._err(400, "Heç bir mərhələ seçilməyib")
        wordlist = (body.get("wordlist") or "").strip() or None
        if wordlist and not Path(wordlist).exists():
            return self._err(400, f"Wordlist tapılmadı: {wordlist}")
        scan_id = db.create_scan(target, stages, wordlist)
        start_scan(scan_id)
        self._json(200, {"id": scan_id})

    def _export(self, sid: int | None, kind: str) -> None:
        if sid is None or not db.get_scan(sid):
            return self._err(404, "Scan yoxdur")
        rows = db.get_findings(sid, "subs")
        if not rows:
            rows = [f for f in db.get_findings(sid) if f["category"] in {"subs", "probe"}]
        if kind == "csv":
            lines = ["host,url,ip,sources_or_detail"]
            for r in rows:
                host = host_from(r.get("url") or r["title"])
                lines.append(
                    f"{host},{r.get('url') or ''},{r.get('ip') or ''},{(r.get('detail') or '').replace(',', ' ')}"
                )
            body = ("\n".join(lines) + "\n").encode("utf-8")
            ctype = "text/csv; charset=utf-8"
            name = f"subdomains-{sid}.csv"
        else:
            hosts = []
            seen = set()
            for r in rows:
                host = host_from(r.get("url") or r["title"])
                if host and host not in seen:
                    seen.add(host)
                    hosts.append(host)
            body = ("\n".join(hosts) + "\n").encode("utf-8")
            ctype = "text/plain; charset=utf-8"
            name = f"subdomains-{sid}.txt"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.end_headers()
        self.wfile.write(body)

    def _demo(self) -> None:
        sid = db.create_scan("demo.local", ["subs", "probe", "ports", "dirs", "nuclei"], None)
        db.update_scan(sid, status="done", current_stage="done")
        samples = [
            ("subs", "www.demo.local", "subdomain", "info"),
            ("subs", "api.demo.local", "subdomain", "info"),
            ("subs", "dev.demo.local", "subdomain", "low"),
            ("probe", "https://www.demo.local", "200 · example title", "info"),
            ("probe", "https://dev.demo.local", "403 Forbidden", "low"),
            ("ports", "203.0.113.10:443", "https", "info"),
            ("ports", "203.0.113.10:22", "ssh", "low"),
            ("dirs", "https://www.demo.local/admin", "status 302", "low"),
            ("dirs", "https://dev.demo.local/.git/HEAD", "status 200", "medium"),
            ("source", "Google API key", "AIzaSy•••••••• (nümunə) @ https://www.demo.local/app.js", "high"),
            ("source", "Firebase URL", "demo-local.firebaseio.com @ https://www.demo.local/app.js", "medium"),
            ("source", "Daxili IP", "10.0.4.12 @ https://api.demo.local/main.js", "medium"),
            ("source", "In-scope host", "internal-api.demo.local @ https://www.demo.local/app.js", "info"),
            ("nuclei", "[medium] expired TLS certificate", "demo.local", "medium"),
            ("nuclei", "[low] missing security header", "x-frame-options", "low"),
        ]
        for cat, title, detail, sev in samples:
            url = guess_url(title, "demo.local")
            ip = "203.0.113.10" if cat in {"subs", "probe"} else ""
            fid = db.add_finding(sid, cat, title, detail, sev, url=url, ip=ip)
            if cat == "subs" and "www" in title:
                db.add_note(fid, "nümunə qeyd: login səhifəsi")
        db.add_log(sid, "ok", "Demo data yükləndi — real target deyil")
        self._json(200, {"id": sid})

    def _file(self, path: Path) -> None:
        path = path.resolve()
        if STATIC.resolve() not in path.parents and path != STATIC.resolve():
            if not str(path).startswith(str(STATIC.resolve())):
                return self._err(403, "Forbidden")
        if not path.is_file():
            return self._err(404, "Fayl yoxdur")
        data = path.read_bytes()
        self._send(200, data, MIME.get(path.suffix, "application/octet-stream"))


def _id_from(path: str, prefix: str, suffix: str) -> int | None:
    mid = path[len(prefix) :]
    if suffix:
        if not mid.endswith(suffix):
            return None
        mid = mid[: -len(suffix)]
    mid = mid.strip("/")
    return int(mid) if mid.isdigit() else None


def main() -> None:
    db.init()
    host, port = "127.0.0.1", 8080
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"PenCentral UI → http://{host}:{port}")
    print("Yalnız icazəli target. Ctrl+C ilə dayan.")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
