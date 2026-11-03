"""Point d'entrée du pipeline d'analyse de logs."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from pathlib import Path

from log_engine.ingestion import parse_logs, read_multiple_logs
from log_engine.transform import TransformedEntry, transform

DEFAULT_FILES = sorted((Path(__file__).parent / "data").glob("*.log"))


def build_pipeline(paths: list[Path]) -> Iterator[TransformedEntry]:
    lines = read_multiple_logs(paths)
    entries = parse_logs(lines)
    return transform(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyse de flux de logs")
    parser.add_argument("files", nargs="*", type=Path, default=DEFAULT_FILES)
    args = parser.parse_args(argv)

    count = 0
    for entry in build_pipeline(args.files):
        count += 1
        print(f"{entry['summary']}  [{entry['channel']}] {entry['payload']}")
    print(f"\n{count} entrées valides après transformation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
