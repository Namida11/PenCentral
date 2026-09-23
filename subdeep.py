#!/usr/bin/env python3
"""SubDeep — güclü subdomain enum: CT + arxiv + JS/source + sourcemap + lokal alətlər."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from modules.subdeep import run_subdeep
from modules.utils import log


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "SubDeep: passiv mənbələr + saytın HTML/JS/source-map-indən "
            "subdomain çıxarır. Yalnız icazəli target."
        )
    )
    p.add_argument("-d", "--domain", required=True, help="example.com")
    p.add_argument("-o", "--outdir", default="output/subdeep", help="çıxış qovluğu")
    p.add_argument("--no-crawl", action="store_true", help="HTML/JS analizini bağla")
    p.add_argument("--no-tools", action="store_true", help="subfinder/assetfinder işlətmə")
    p.add_argument("--mutate", action="store_true", help="tapılan tokenlərdən kiçik permutasiya")
    p.add_argument("--resolve", action="store_true", help="DNS resolve et")
    p.add_argument("--max-js", type=int, default=40, help="maksimum JS/source fayl")
    args = p.parse_args()

    domain = args.domain.strip().lower().removeprefix("https://").removeprefix("http://")
    domain = domain.split("/")[0]
    if not domain or "." not in domain:
        log("Domain düzgün deyil", "err")
        sys.exit(2)

    log("Yalnız yazılı icazəsi olan target-də işlət.", "warn")
    out = Path(args.outdir) / domain
    path = run_subdeep(
        domain,
        out,
        crawl=not args.no_crawl,
        mutate=args.mutate,
        resolve=args.resolve,
        use_local_tools=not args.no_tools,
        max_js=args.max_js,
    )
    log(f"Siyahı: {path}", "ok")
    log(f"Mənbə xəritəsi: {out / 'subdomains_by_source.json'}", "ok")


if __name__ == "__main__":
    main()
