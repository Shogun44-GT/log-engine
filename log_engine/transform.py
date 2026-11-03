"""Module 2 : filtrage, normalisation et routage fonctionnels des logs."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from log_engine.ingestion import LEVELS, LogEntry

LOWERCASE_VALUE_KEYS: frozenset[str] = frozenset({"action", "status"})


class TransformedEntry(LogEntry, total=False):
    summary: str
    channel: str
    target: str


def filter_entries(entries: Iterable[LogEntry | None]) -> Iterator[LogEntry]:
    """Retire les None puis les entrées sans utilisateur ou sans IP."""
    parsed = filter(None, entries)
    return filter(
        lambda e: bool(e["user"]) and bool(e["ip"]) and e["level"] in LEVELS,
        parsed,
    )


def _normalize_payload(payload: dict | str) -> dict | str:
    if isinstance(payload, str):
        return " ".join(payload.split())
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        new_key = str(key).strip().lower()
        if isinstance(value, str):
            value = value.strip()
            if new_key in LOWERCASE_VALUE_KEYS:
                value = value.lower()
        cleaned[new_key] = value
    return cleaned


def normalize_entry(entry: LogEntry) -> TransformedEntry:
    """Renvoie une copie nettoyée de l'entrée, avec un résumé lisible."""
    raw_ip, port, raw_protocol = entry["meta"]
    ip = raw_ip.strip()
    protocol = raw_protocol.strip().upper()
    user = entry["user"].strip().lower()
    level = entry["level"].strip().upper()
    normalized: TransformedEntry = {
        "timestamp": entry["timestamp"],
        "level": level,
        "ip": ip,
        "user": user,
        "payload": _normalize_payload(entry["payload"]),
        "meta": (ip, port, protocol),
    }
    normalized["summary"] = (
        f"[{entry['timestamp']:%Y-%m-%d %H:%M:%S}] {level:<8} "
        f"{user}@{ip}:{port}/{protocol}"
    )
    return normalized


def normalize(entries: Iterable[LogEntry]) -> Iterator[TransformedEntry]:
    """Applique normalize_entry à chaque entrée avec map()."""
    return map(normalize_entry, entries)


def route(record: object) -> tuple[str, Any]:
    """Classe un enregistrement selon son format avec match-case."""
    match record:
        case (str() as ip, int() as port, str() as protocol):
            return ("connection", f"{ip}:{port}/{protocol}")
        case {"level": "ERROR" | "CRITICAL" as level, "code": int() as code}:
            return ("error", f"{level} {code}")
        case {"action": "login", "status": "failed"}:
            return ("auth_failure", "login failed")
        case {"action": "login", "status": str() as status}:
            return ("auth", f"login {status}")
        case dict():
            return ("event", record)
        case str() if record.strip():
            return ("raw", record)
        case _:
            return ("unknown", record)


def route_entry(entry: TransformedEntry) -> TransformedEntry:
    """Ajoute à l'entrée son canal (payload) et sa cible (tuple meta)."""
    match entry["payload"]:
        case dict() as payload:
            record: object = {"level": entry["level"], **payload}
        case other:
            record = other
    channel, _ = route(record)
    _, target = route(entry["meta"])
    return {**entry, "channel": channel, "target": target}


def route_all(
    entries: Iterable[TransformedEntry],
) -> Iterator[TransformedEntry]:
    """Applique route_entry à chaque entrée avec map()."""
    return map(route_entry, entries)


def transform(
    entries: Iterable[LogEntry | None],
) -> Iterator[TransformedEntry]:
    """Chaîne complète du module 2 : filtre, normalisation, routage."""
    return route_all(normalize(filter_entries(entries)))
