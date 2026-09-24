from __future__ import annotations

from pathlib import Path

from .utils import log, require_or_skip, run_cmd, unique_lines, write_lines


def run_subdomains(domain: str, outdir: Path) -> Path:
    """SubDeep: CT, arxiv, JS/source, sourcemap + lokal alətlər."""
    from .subdeep import run_subdeep

    return run_subdeep(
        domain,
        outdir,
        crawl=True,
        mutate=False,
        resolve=False,
        use_local_tools=True,
        max_js=12,
    )


def _httpx_is_projectdiscovery(bin_path: str) -> bool:
    """PATH-dəki httpx çox vaxt Python httpx CLI-dir, PD httpx deyil."""
    from .utils import run_cmd

    proc = run_cmd([bin_path, "-version"], timeout=8)
    blob = (proc.stdout or "") + (proc.stderr or "")
    return "projectdiscovery" in blob.lower() or "Current Version" in blob


def run_probe(hosts_file: Path, outdir: Path) -> Path:
    """Canlı HTTP/S hostlar — builtin probe (PD httpx varsa ondan da istifadə)."""
    live = outdir / "live_urls.txt"
    verbose = outdir / "httpx_verbose.txt"
    httpx = require_or_skip("httpx")
    if httpx and _httpx_is_projectdiscovery(httpx):
        run_cmd(
            [
                httpx,
                "-l",
                str(hosts_file),
                "-silent",
                "-status-code",
                "-title",
                "-follow-redirects",
                "-timeout",
                "10",
                "-threads",
                "50",
            ],
            outfile=verbose,
            timeout=900,
        )
        urls: list[str] = []
        for line in unique_lines(verbose):
            token = line.split()[0] if line.split() else ""
            if token.startswith("http"):
                urls.append(token)
        write_lines(live, urls)
        log(f"Live URL: {len(urls)}", "ok")
        return live

    from .preview import probe_hosts

    lines = probe_hosts(unique_lines(hosts_file), verbose)
    write_lines(live, [ln.split()[0] for ln in lines if ln.startswith("http")])
    log(f"Live URL (builtin): {len(unique_lines(live))}", "ok")
    return live


def run_ports(hosts_file: Path, outdir: Path) -> Path:
    """Sürətli port kəşfiyyatı: naabu üstünlük, yoxdursa nmap top ports."""
    ports_out = outdir / "open_ports.txt"
    hosts = unique_lines(hosts_file)
    if not hosts:
        write_lines(ports_out, [])
        return ports_out

    naabu = require_or_skip("naabu")
    if naabu:
        run_cmd(
            [
                naabu,
                "-list",
                str(hosts_file),
                "-top-ports",
                "100",
                "-silent",
                "-rate",
                "1000",
            ],
            outfile=ports_out,
            timeout=1200,
        )
        log(f"Naabu: {len(unique_lines(ports_out))} host:port", "ok")
        return ports_out

    nmap = require_or_skip("nmap")
    if nmap:
        # Host siyahısı nmap formatında
        run_cmd(
            [
                nmap,
                "-iL",
                str(hosts_file),
                "-T4",
                "--top-ports",
                "100",
                "-oG",
                str(outdir / "nmap.gnmap"),
            ],
            outfile=outdir / "nmap_stdout.txt",
            timeout=1800,
        )
        parsed: list[str] = []
        gnmap = outdir / "nmap.gnmap"
        if gnmap.exists():
            for line in gnmap.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "Ports:" not in line or "Host:" not in line:
                    continue
                # Host: 1.2.3.4 () Ports: 80/open/tcp//http///
                try:
                    host = line.split()[1]
                except IndexError:
                    continue
                after = line.split("Ports:", 1)[-1]
                for part in after.split(","):
                    part = part.strip()
                    if "/open/" in part:
                        port = part.split("/")[0].strip()
                        parsed.append(f"{host}:{port}")
        write_lines(ports_out, parsed)
        log(f"Nmap parse: {len(parsed)} open port", "ok")
        return ports_out

    write_lines(ports_out, [])
    return ports_out


def run_dirs(live_urls: Path, outdir: Path, wordlist: str | None) -> Path:
    """Hər aktiv subdomain üçün dirsearch / ffuf / ferox / gobuster."""
    found = outdir / "directories.txt"
    urls = [u.split()[0] for u in unique_lines(live_urls) if u.startswith("http")]
    if not urls:
        write_lines(found, [])
        return found
    if not wordlist or not Path(wordlist).exists():
        log("Wordlist yoxdur — directory enum skip. SecLists yolu ver.", "warn")
        write_lines(found, [])
        return found

    hits: list[str] = []
    tools = {
        "ffuf": require_or_skip("ffuf"),
        "dirsearch": require_or_skip("dirsearch"),
        "feroxbuster": require_or_skip("feroxbuster"),
        "gobuster": require_or_skip("gobuster"),
    }
    present = [k for k, v in tools.items() if v]
    if not present:
        log("ffuf/dirsearch/feroxbuster/gobuster yoxdur", "warn")
        write_lines(found, [])
        return found

    log(f"Dir enum alətləri: {', '.join(present)} · {len(urls)} target", "step")
    for url in urls[:40]:
        base = url.rstrip("/")
        if tools["ffuf"]:
            raw = outdir / "ffuf_raw.txt"
            proc = run_cmd(
                [
                    tools["ffuf"], "-u", base + "/FUZZ", "-w", wordlist,
                    "-mc", "200,201,204,301,302,307,308,401,403,405,500",
                    "-t", "30", "-timeout", "8", "-s",
                ],
                outfile=raw,
                timeout=480,
            )
            for line in (proc.stdout or "").splitlines():
                if line.strip():
                    hits.append(f"{base} :: ffuf :: {line.strip()}")
        if tools["dirsearch"]:
            raw = outdir / "dirsearch_raw.txt"
            proc = run_cmd(
                [
                    tools["dirsearch"], "-u", base, "-w", wordlist,
                    "--format=plain", "-q", "--timeout=8",
                ],
                outfile=raw,
                timeout=480,
            )
            for line in (proc.stdout or "").splitlines():
                if line.strip() and not line.startswith("#"):
                    hits.append(f"{base} :: dirsearch :: {line.strip()}")
        if tools["feroxbuster"]:
            raw = outdir / "ferox_raw.txt"
            proc = run_cmd(
                [
                    tools["feroxbuster"], "-u", base, "-w", wordlist,
                    "-q", "--timeout", "8", "-n",
                    "--status-codes", "200,201,204,301,302,307,401,403,405,500",
                ],
                outfile=raw,
                timeout=480,
            )
            for line in (proc.stdout or "").splitlines():
                if line.strip():
                    hits.append(f"{base} :: ferox :: {line.strip()}")
        if tools["gobuster"]:
            raw = outdir / "gobuster_raw.txt"
            proc = run_cmd(
                [
                    tools["gobuster"], "dir", "-u", base, "-w", wordlist,
                    "-q", "-t", "30", "--timeout", "8s",
                    "-s", "200,204,301,302,307,401,403,500",
                ],
                outfile=raw,
                timeout=480,
            )
            for line in (proc.stdout or "").splitlines():
                if line.strip():
                    hits.append(f"{base} :: gobuster :: {line.strip()}")

    write_lines(found, hits)
    log(f"Directory hit: {len(hits)}", "ok")
    return found


def run_nuclei(live_urls: Path, outdir: Path, severity: str) -> Path:
    findings = outdir / "nuclei.txt"
    urls = unique_lines(live_urls)
    if not urls:
        write_lines(findings, [])
        return findings
    nuclei = require_or_skip("nuclei")
    if not nuclei:
        write_lines(findings, [])
        return findings
    run_cmd(
        [
            nuclei,
            "-l",
            str(live_urls),
            "-severity",
            severity,
            "-silent",
            "-rate-limit",
            "50",
            "-timeout",
            "8",
            "-retries",
            "1",
        ],
        outfile=findings,
        timeout=3600,
    )
    log(f"Nuclei hit: {len(unique_lines(findings))}", "ok")
    return findings


def write_summary(outdir: Path, domain: str, files: dict[str, Path]) -> Path:
    summary = outdir / "SUMMARY.md"
    lines = [
        f"# PenCentral report — {domain}",
        "",
        f"Qovluq: `{outdir}`",
        "",
        "| Mərhələ | Fayl | Sətir |",
        "|---|---|---|",
    ]
    for name, path in files.items():
        count = len(unique_lines(path)) if path.exists() else 0
        lines.append(f"| {name} | `{path.name}` | {count} |")
    lines += [
        "",
        "Növbəti addımlar insan qərarıdır: false-positive təmizlə, scope yoxla, "
        "yalnız icazəli tapıntıları report et.",
        "",
    ]
    summary.write_text("\n".join(lines), encoding="utf-8")
    return summary
