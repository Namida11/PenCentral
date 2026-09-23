from __future__ import annotations

import threading
from pathlib import Path

from . import db
from . import pipeline
from .preview import guess_url, host_from, resolve_ips, screenshot_url
from .utils import add_log_sink, log, remove_log_sink, stamp, unique_lines, write_lines

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "output"

NUCLEI_SEV = {
    "light": "medium,high,critical",
    "standard": "low,medium,high,critical",
    "full": "info,low,medium,high,critical",
}

_running_lock = threading.Lock()
_current_thread: threading.Thread | None = None


def ingest_file(scan_id: int, category: str, path: Path, severity: str = "info") -> int:
    n = 0
    for line in unique_lines(path):
        title, detail, sev = _parse_line(category, line, severity)
        url = guess_url(title)
        db.add_finding(scan_id, category, title, detail, sev, url=url)
        n += 1
    return n


def enrich_previews(scan_id: int, target: str, outdir: Path, live_file: Path) -> None:
    shots = outdir / "shots"
    shots.mkdir(parents=True, exist_ok=True)
    live_urls = unique_lines(live_file) if live_file.exists() else []
    live_hosts = {host_from(u) for u in live_urls}

    findings = db.get_findings(scan_id)
    taken = 0
    max_shots = 30
    for item in findings:
        if item["category"] not in {"subs", "probe"}:
            continue
        url = item.get("url") or guess_url(item["title"], target)
        host = host_from(url or item["title"])
        ip = resolve_ips(host)
        fields = {"url": url, "ip": ip}
        want_shot = taken < 24
        shot_path = shots / f"{host or item['id']}.png"
        if want_shot and not item.get("screenshot"):
            if screenshot_url(url, shot_path):
                fields["screenshot"] = str(shot_path)
                taken += 1
        db.update_finding(item["id"], **fields)
    db.add_log(scan_id, "ok", f"Preview: {taken} screenshot, IP-lər yazıldı")


def _parse_line(category: str, line: str, default_sev: str) -> tuple[str, str, str]:
    sev = default_sev
    title = line
    detail = ""
    low = line.lower()
    if category == "nuclei":
        for token in ("critical", "high", "medium", "low", "info"):
            if f"[{token}]" in low:
                sev = token
                break
        title = line[:180]
        detail = line
    elif category == "probe":
        parts = line.split()
        title = parts[0] if parts else line
        detail = line
        if any(x in line for x in (" 200 ", "[200]", " 200[")):
            sev = "info"
        elif any(x in line for x in (" 403 ", " 401 ")):
            sev = "low"
    elif category == "ports":
        title = line
        detail = "Açıq port"
        if line.endswith(("22", ":22")):
            sev = "low"
        elif any(line.endswith(p) or line.endswith(":" + p) for p in ("3389", "445", "3306", "5432", "27017")):
            sev = "medium"
    elif category == "dirs":
        title = line[:180]
        detail = line
        if any(x in low for x in (".git", ".env", "backup", "wp-admin", "phpinfo")):
            sev = "medium"
    else:
        title = line
        detail = category
    return title, detail, sev


def start_scan(scan_id: int) -> None:
    global _current_thread
    t = threading.Thread(target=_execute, args=(scan_id,), daemon=True)
    with _running_lock:
        _current_thread = t
    t.start()


def _execute(scan_id: int) -> None:
    scan = db.get_scan(scan_id)
    if not scan:
        return

    def sink(level: str, message: str) -> None:
        db.add_log(scan_id, level, message)

    add_log_sink(sink)
    db.update_scan(scan_id, status="running", current_stage="start")
    db.add_log(scan_id, "step", f"Scan başladı: {scan['target']}")

    try:
        target = scan["target"].strip().lower()
        stages = [s for s in scan["stages"].split(",") if s]
        wordlist = scan["wordlist"] or None
        outdir = OUTPUT / target.replace("/", "_") / f"{stamp()}_scan{scan_id}"
        outdir.mkdir(parents=True, exist_ok=True)

        hosts = outdir / "subdomains.txt"
        live = outdir / "live_urls.txt"
        write_lines(hosts, [target])

        if "subs" in stages:
            db.update_scan(scan_id, current_stage="subs")
            db.add_log(scan_id, "step", "Subdomain axtarışı")
            hosts = pipeline.run_subdomains(target, outdir)
            n = ingest_file(scan_id, "subs", hosts)
            db.add_log(scan_id, "ok", f"{n} subdomain")

        if "probe" in stages:
            db.update_scan(scan_id, current_stage="probe")
            db.add_log(scan_id, "step", "Live host / HTTP probe")
            live = pipeline.run_probe(hosts, outdir)
            verbose = outdir / "httpx_verbose.txt"
            src = verbose if verbose.exists() else live
            n = ingest_file(scan_id, "probe", src)
            db.add_log(scan_id, "ok", f"{n} live nəticə")
        else:
            write_lines(live, [])

        if "ports" in stages:
            db.update_scan(scan_id, current_stage="ports")
            db.add_log(scan_id, "step", "Port scan")
            ports = pipeline.run_ports(hosts, outdir)
            n = ingest_file(scan_id, "ports", ports)
            db.add_log(scan_id, "ok", f"{n} açıq port")

        if "dirs" in stages:
            db.update_scan(scan_id, current_stage="dirs")
            db.add_log(scan_id, "step", "Directory enum")
            dirs = pipeline.run_dirs(live, outdir, wordlist)
            n = ingest_file(scan_id, "dirs", dirs)
            db.add_log(scan_id, "ok", f"{n} directory")

        db.update_scan(scan_id, current_stage="preview")
        db.add_log(scan_id, "step", "IP + web görüntü")
        enrich_previews(scan_id, target, outdir, live)

        if "nuclei" in stages:
            db.update_scan(scan_id, current_stage="nuclei")
            db.add_log(scan_id, "step", "Nuclei")
            profile = "full" if "dirs" in stages else "standard"
            if stages == ["subs", "probe"]:
                profile = "light"
            findings = pipeline.run_nuclei(live, outdir, NUCLEI_SEV[profile])
            n = ingest_file(scan_id, "nuclei", findings)
            db.add_log(scan_id, "ok", f"{n} nuclei tapıntı")

        db.update_scan(
            scan_id,
            status="done",
            current_stage="done",
            finished_at=__import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        )
        db.add_log(scan_id, "ok", "Scan bitdi")
    except Exception as exc:
        db.update_scan(scan_id, status="error", error=str(exc), current_stage="error")
        db.add_log(scan_id, "err", f"Xəta: {exc}")
        log(f"scan {scan_id} failed: {exc}", "err")
    finally:
        remove_log_sink(sink)
