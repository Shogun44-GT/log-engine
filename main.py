"""Point d'entrée du pipeline d'analyse de logs.

Pipeline complet, en flux (rien n'est chargé entièrement en RAM) :
  module 1 (ingestion) -> module 2 (transform)
    -> module 4 (règles de sécurité, affichage entrée par entrée)
    -> module 3 (agrégation, en seconde passe sur les fichiers)
    -> audit d'introspection (globals() / locals()).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from pathlib import Path

from log_engine.aggregation import analyze, format_report
from log_engine.ingestion import parse_logs, read_multiple_logs
from log_engine.rules import (
    apply_security_rules,
    audit_runtime,
    export_audit_report,
    format_audit_report,
)
from log_engine.transform import TransformedEntry, transform

DEFAULT_FILES = sorted((Path(__file__).parent / "data").glob("*.log"))
BLACKLIST = frozenset({"10.0.0.5"})


def build_pipeline(paths: list[Path]) -> Iterator[TransformedEntry]:
    lines = read_multiple_logs(paths)
    entries = parse_logs(lines)
    return transform(entries)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyse de flux de logs")
    parser.add_argument("files", nargs="*", type=Path, default=DEFAULT_FILES)
    parser.add_argument(
        "--audit",
        type=Path,
        default=None,
        help="chemin du rapport d'audit JSON à exporter",
    )
    args = parser.parse_args(argv)

    # Passe 1 — module 4 : règles de sécurité, entrée par entrée.
    count = 0
    alerted = 0
    for entry in apply_security_rules(
        entries=build_pipeline(args.files), blacklist=BLACKLIST
    ):
        count += 1
        alerts = entry["alerts"]
        if alerts:
            alerted += 1
        print(
            f"{entry['summary']}  [{entry['channel']}] {entry['payload']}",
            end="",
        )
        if alerts:
            print(f"  ALERTES: {', '.join(alerts)}", end="")
        print()
    print(
        f"\n{count} entrées valides après transformation, "
        f"{alerted} avec alerte(s)"
    )

    # Passe 2 — module 3 : agrégation (nouvelle lecture, toujours en flux).
    report = analyze(build_pipeline(args.files), blacklist=BLACKLIST)
    print()
    print(format_report(report))

    # Audit d'introspection — module 4.
    audit = audit_runtime(globals(), locals())
    print()
    print(format_audit_report(audit))
    if args.audit is not None:
        export_audit_report(audit, args.audit)
        print(f"Rapport d'audit exporté : {args.audit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
