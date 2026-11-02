"""Point d'entrée du pipeline d'analyse de logs."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from pathlib import Path

from log_engine.ingestion import LogEntry, parse_logs, read_multiple_logs

DEFAULT_FILES = sorted((Path(__file__).parent / "data").glob("*.log"))


def build_pipeline(paths: list[Path]) -> Iterator[LogEntry | None]:
    lines = read_multiple_logs(paths)
    return parse_logs(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyse de flux de logs")
    parser.add_argument("files", nargs="*", type=Path, default=DEFAULT_FILES)
    args = parser.parse_args(argv)

    total = 0
    valid = 0
    for entry in build_pipeline(args.files):
        total += 1
        if entry is None:
            continue
        valid += 1
        print(
            f"{entry['timestamp']:%H:%M:%S} {entry['level']:<8} "
            f"{entry['meta']} {entry['user']:<6} {entry['payload']}"
        )
    print(f"\n{valid} lignes valides / {total} lues")
    return 0


if __name__ == "__main__":
    sys.exit(main())
