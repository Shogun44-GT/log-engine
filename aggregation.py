"""Module 3 : agrégation, ensembles et détection de force brute.

Le flux d'entrées (sortie de ``transform``) est parcouru **une seule fois**
et par blocs de taille bornée : aucune liste complète n'est jamais montée
en mémoire. Seuls les agrégats (ensembles d'IP, compteurs, séries en cours)
sont conservés, et leur taille dépend du nombre de valeurs distinctes,
pas du nombre de lignes.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from itertools import islice
from typing import NamedTuple

from log_engine.transform import TransformedEntry

ERROR_LEVELS: frozenset[str] = frozenset({"ERROR", "CRITICAL"})
AUTH_CHANNELS: frozenset[str] = frozenset({"auth", "auth_failure"})

# Blacklist de démonstration : immuable, donc non modifiable par erreur.
DEFAULT_BLACKLIST: frozenset[str] = frozenset(
    {"203.0.113.7", "198.51.100.4", "45.33.32.156"}
)
DEFAULT_THRESHOLD = 5
DEFAULT_CHUNK_SIZE = 1000


class SetComparison(NamedTuple):
    """Résultat des opérations ensemblistes entre IP actives et blacklist."""

    union: frozenset[str]
    intersection: frozenset[str]
    only_active: frozenset[str]
    only_blacklist: frozenset[str]
    symmetric_difference: frozenset[str]


@dataclass
class BruteForceAlert:
    """Série d'échecs de connexion consécutifs depuis une même IP."""

    ip: str
    first_seen: datetime
    last_seen: datetime
    attempts: int = 0
    users: set[str] = field(default_factory=set)


@dataclass
class AnalysisReport:
    """Synthèse complète produite par :func:`analyze`."""

    entries_scanned: int
    cycles_completed: int
    completed: bool
    error_ips: frozenset[str]
    active_ips: frozenset[str]
    by_channel: dict[str, int]
    by_user: dict[str, int]
    by_level: dict[str, int]
    blacklist: SetComparison
    alerts: list[BruteForceAlert]


def compare_with_blacklist(
    active_ips: Iterable[str],
    blacklist: frozenset[str] = DEFAULT_BLACKLIST,
) -> SetComparison:
    """Applique ``|``, ``&``, ``-`` et ``^`` entre IP actives et blacklist."""
    active = frozenset(active_ips)
    return SetComparison(
        union=active | blacklist,
        intersection=active & blacklist,
        only_active=active - blacklist,
        only_blacklist=blacklist - active,
        symmetric_difference=active ^ blacklist,
    )


def analyze(
    entries: Iterable[TransformedEntry],
    blacklist: frozenset[str] = DEFAULT_BLACKLIST,
    threshold: int = DEFAULT_THRESHOLD,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_alerts: int | None = None,
) -> AnalysisReport:
    """Parcourt le flux une fois et produit ensembles, compteurs et alertes.

    Force brute : ``threshold`` échecs de connexion consécutifs depuis une
    même IP. Un succès de connexion de cette IP remet sa série à zéro ; les
    autres événements ne l'affectent pas. Une alerte est émise quand la série
    atteint le seuil, puis son compteur continue de croître tant qu'elle dure.

    Si ``max_alerts`` est atteint, l'analyse s'arrête tôt et ``completed``
    vaut ``False`` : le flux n'est alors pas consommé jusqu'au bout.
    """
    if threshold < 1:
        raise ValueError("threshold doit être >= 1")
    if chunk_size < 1:
        raise ValueError("chunk_size doit être >= 1")

    iterator = iter(entries)
    error_ips: set[str] = set()
    active_ips: set[str] = set()
    by_channel: defaultdict[str, int] = defaultdict(int)
    by_user: defaultdict[str, int] = defaultdict(int)
    by_level: defaultdict[str, int] = defaultdict(int)
    streaks: dict[str, BruteForceAlert] = {}
    alerts: list[BruteForceAlert] = []
    scanned = 0
    cycles = 0
    completed = True

    while True:
        chunk = tuple(islice(iterator, chunk_size))
        if not chunk:
            break  # flux épuisé
        for entry in chunk:
            scanned += 1
            channel = entry.get("channel", "unknown")
            ip = entry["ip"]
            by_channel[channel] += 1
            by_user[entry["user"]] += 1
            by_level[entry["level"]] += 1
            active_ips.add(ip)
            if entry["level"] in ERROR_LEVELS:
                error_ips.add(ip)

            if channel not in AUTH_CHANNELS:
                continue
            if channel == "auth":
                streaks.pop(ip, None)  # connexion réussie : série rompue
                continue

            streak = streaks.get(ip)
            if streak is None:
                streak = BruteForceAlert(ip, entry["timestamp"], entry["timestamp"])
                streaks[ip] = streak
            streak.attempts += 1
            streak.last_seen = entry["timestamp"]
            streak.users.add(entry["user"])
            if streak.attempts == threshold:
                alerts.append(streak)
                if max_alerts is not None and len(alerts) >= max_alerts:
                    break
        else:
            cycles += 1  # bloc entièrement traité, sans interruption
            continue
        completed = False  # sortie par break : détection interrompue
        break

    return AnalysisReport(
        entries_scanned=scanned,
        cycles_completed=cycles,
        completed=completed,
        error_ips=frozenset(error_ips),
        active_ips=frozenset(active_ips),
        by_channel=dict(by_channel),
        by_user=dict(by_user),
        by_level=dict(by_level),
        blacklist=compare_with_blacklist(active_ips, blacklist),
        alerts=alerts,
    )


def format_report(report: AnalysisReport) -> str:
    """Met en forme un rapport pour l'affichage en console."""
    lines = [
        f"Entrées analysées : {report.entries_scanned} "
        f"({'analyse complète' if report.completed else 'interrompue'})",
        f"Par canal  : {report.by_channel}",
        f"Par user   : {report.by_user}",
        f"Par niveau : {report.by_level}",
        f"IP en erreur       : {sorted(report.error_ips)}",
        f"IP actives         : {sorted(report.active_ips)}",
        f"IP actives et blacklistées : {sorted(report.blacklist.intersection)}",
        f"IP actives non blacklistées : {sorted(report.blacklist.only_active)}",
        f"IP blacklistées inactives   : {sorted(report.blacklist.only_blacklist)}",
        f"Différence symétrique       : "
        f"{sorted(report.blacklist.symmetric_difference)}",
    ]
    if report.alerts:
        for alert in report.alerts:
            lines.append(
                f"ALERTE force brute : {alert.ip} - {alert.attempts} échecs "
                f"consécutifs ({alert.first_seen:%H:%M:%S} -> "
                f"{alert.last_seen:%H:%M:%S}), users={sorted(alert.users)}"
            )
    else:
        lines.append("Aucune attaque par force brute détectée.")
    return "\n".join(lines)
