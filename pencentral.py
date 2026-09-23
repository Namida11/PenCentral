#!/usr/bin/env python3
"""PenCentral — icazəli pentest/recon üçün mərkəzi orchestrator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from modules.pipeline import (
    run_dirs,
    run_nuclei,
    run_ports,
    run_probe,
    run_subdomains,
    write_summary,
)
from modules.utils import confirm_scope, log, stamp, unique_lines, write_lines

PROFILES = {
    "light": ["subs", "probe"],
    "standard": ["subs", "probe", "ports", "nuclei"],
    "full": ["subs", "probe", "ports", "dirs", "nuclei"],
}

NUCLEI_SEV = {
    "light": "medium,high,critical",
    "standard": "low,medium,high,critical",
    "full": "info,low,medium,high,critical",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="PenCentral — subdomain, probe, port, dir enum və nuclei bir yerdə.",
        epilog="Yalnız yazılı icazə olan target-lərdə işlət.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain", help="Tək domain (example.com)")
    g.add_argument("-l", "--list", help="Target siyahısı (hər sətirdə bir domain)")
    p.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="standard",
        help="light | standard | full",
    )
    p.add_argument(
        "--only",
        help="Vergüllə mərhələ: subs,probe,ports,dirs,nuclei",
    )
    p.add_argument("--wordlist", help="Directory enum wordlist-i")
    p.add_argument(
        "-o",
        "--outdir",
        default="output",
        help="Nəticə kök qovluğu (default: output)",
    )
    p.add_argument("-y", "--yes", action="store_true", help="Scope təsdiqini keç")
    return p.parse_args()


def load_targets(args: argparse.Namespace) -> list[str]:
    if args.domain:
        return [args.domain.strip().lower()]
    path = Path(args.list)
    if not path.exists():
        log(f"Siyahı tapılmadı: {path}", "err")
        sys.exit(2)
    return unique_lines(path)


def stages_for(args: argparse.Namespace) -> list[str]:
    if args.only:
        wanted = [s.strip() for s in args.only.split(",") if s.strip()]
        valid = {"subs", "probe", "ports", "dirs", "nuclei"}
        bad = [s for s in wanted if s not in valid]
        if bad:
            log(f"Naməlum mərhələ: {bad}", "err")
            sys.exit(2)
        return wanted
    return list(PROFILES[args.profile])


def run_one(domain: str, stages: list[str], args: argparse.Namespace) -> None:
    outdir = Path(args.outdir) / domain.replace("/", "_") / stamp()
    outdir.mkdir(parents=True, exist_ok=True)
    log(f"=== {domain} → {outdir} ===", "step")

    files: dict[str, Path] = {}
    hosts = outdir / "subdomains.txt"
    live = outdir / "live_urls.txt"

    if "subs" in stages:
        hosts = run_subdomains(domain, outdir)
        files["subdomains"] = hosts
    else:
        write_lines(hosts, [domain])

    if "probe" in stages:
        live = run_probe(hosts, outdir)
        files["live"] = live
    else:
        # probe yoxdursa nuclei/dirs üçün domain-i URL kimi yoxlamaq olmaz;
        # host adlarını saxla, operator özü qərar versin
        write_lines(live, [])

    if "ports" in stages:
        files["ports"] = run_ports(hosts, outdir)

    if "dirs" in stages:
        files["dirs"] = run_dirs(live, outdir, args.wordlist)

    if "nuclei" in stages:
        sev = NUCLEI_SEV.get(args.profile, "low,medium,high,critical")
        files["nuclei"] = run_nuclei(live, outdir, sev)

    summary = write_summary(outdir, domain, files)
    log(f"Hesabat: {summary}", "ok")


def main() -> None:
    args = parse_args()
    targets = load_targets(args)
    if not targets:
        log("Target yoxdur.", "err")
        sys.exit(2)
    stages = stages_for(args)
    log(f"Mərhələlər: {', '.join(stages)}", "info")
    confirm_scope(targets, assume_yes=args.yes)
    for domain in targets:
        run_one(domain, stages, args)
    log("Bitdi.", "ok")


if __name__ == "__main__":
    main()
