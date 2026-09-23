from __future__ import annotations

import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"


_log_sinks: list = []


def add_log_sink(fn) -> None:
    _log_sinks.append(fn)


def remove_log_sink(fn) -> None:
    if fn in _log_sinks:
        _log_sinks.remove(fn)


def log(msg: str, level: str = "info") -> None:
    palette = {
        "info": Colors.CYAN,
        "ok": Colors.GREEN,
        "warn": Colors.YELLOW,
        "err": Colors.RED,
        "step": Colors.BLUE,
    }
    color = palette.get(level, Colors.RESET)
    print(f"{color}[{level.upper()}]{Colors.RESET} {msg}", flush=True)
    for sink in list(_log_sinks):
        try:
            sink(level, msg)
        except Exception:
            pass


def which(name: str) -> str | None:
    return shutil.which(name)


def require_or_skip(tool: str) -> str | None:
    path = which(tool)
    if not path:
        log(f"`{tool}` tapılmadı — bu mərhələ keçilir. PATH-ə əlavə et.", "warn")
        return None
    return path


def run_cmd(
    cmd: list[str],
    outfile: Path | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    log(" ".join(cmd), "info")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log(f"Timeout: {' '.join(cmd)}", "err")
        raise
    if outfile is not None:
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text(proc.stdout or "", encoding="utf-8")
        if proc.stderr:
            outfile.with_suffix(outfile.suffix + ".err").write_text(
                proc.stderr, encoding="utf-8"
            )
    if proc.returncode != 0:
        log(
            f"Exit {proc.returncode} — {cmd[0]}. stderr-ə bax: "
            f"{(outfile.with_suffix(outfile.suffix + '.err') if outfile else 'console')}",
            "warn",
        )
    return proc


def unique_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    seen: set[str] = set()
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def confirm_scope(targets: list[str], assume_yes: bool) -> None:
    print()
    log("SKAN EDILƏCƏK TARGET-LƏR:", "step")
    for t in targets:
        print(f"  - {t}")
    print()
    log(
        "Yalnız icazəli aktivlərə qarşı işlə. İcazəsiz skan qanunsuzdur.",
        "warn",
    )
    if assume_yes:
        return
    try:
        answer = input("Davam? [y/N]: ").strip().lower()
    except EOFError:
        answer = "n"
    if answer not in {"y", "yes", "hə", "ha"}:
        log("Ləğv edildi.", "err")
        sys.exit(1)
