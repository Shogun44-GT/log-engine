"""Module 1 : ingestion des logs par générateurs et parsing en dictionnaires."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import TypedDict

LEVELS: frozenset[str] = frozenset({"INFO", "WARNING", "ERROR", "CRITICAL"})
SEPARATOR = " | "
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"

Meta = tuple[str, int, str]


class LogEntry(TypedDict):
    timestamp: datetime
    level: str
    ip: str
    user: str
    payload: dict | str
    meta: Meta


def read_logs(path: str | Path, encoding: str = "utf-8") -> Iterator[str]:
    """Lit un fichier ligne par ligne, sans jamais le charger en entier."""
    with open(path, encoding=encoding) as handle:
        for line in handle:
            stripped = line.rstrip("\r\n")
            if stripped.strip():
                yield stripped


def read_multiple_logs(paths: Iterable[str | Path]) -> Iterator[str]:
    """Enchaîne plusieurs fichiers de logs, un par un."""
    for path in paths:
        try:
            yield from read_logs(path)
        except FileNotFoundError:
            print(f"[ingestion] fichier introuvable, ignoré : {path}")
            continue


def _parse_source(source: str) -> Meta:
    address, protocol = source.rsplit("/", 1)
    ip, port = address.rsplit(":", 1)
    return (ip.strip(), int(port), protocol.strip().upper())


def _parse_payload(raw: str) -> dict | str:
    raw = raw.strip()
    if raw.startswith("{"):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return raw
        if isinstance(value, dict):
            return value
    return raw


def parse_line(line: str) -> LogEntry | None:
    """Transforme une ligne brute en LogEntry, ou None si elle est invalide."""
    if not line or not line.strip():
        return None
    parts = line.strip().split(SEPARATOR, 4)
    if len(parts) != 5:
        return None
    raw_ts, raw_level, raw_source, raw_user, raw_payload = parts
    level = raw_level.strip().upper()
    if level not in LEVELS:
        return None
    try:
        timestamp = datetime.strptime(raw_ts.strip(), TIMESTAMP_FORMAT)
        meta = _parse_source(raw_source)
    except ValueError:
        return None
    return {
        "timestamp": timestamp,
        "level": level,
        "ip": meta[0],
        "user": raw_user.strip(),
        "payload": _parse_payload(raw_payload),
        "meta": meta,
    }


def parse_logs(lines: Iterable[str]) -> Iterator[LogEntry | None]:
    """Applique parse_line paresseusement sur un flux de lignes."""
    for line in lines:
        yield parse_line(line)
