"""Module 4 : moteur de règles modulaire et introspection dynamique.

Deux parties :

1. ``apply_security_rules(*args, **kwargs)`` : reçoit un nombre variable de
   fonctions de sécurité (objets de première classe, via ``*args``) et une
   configuration dynamique (via ``**kwargs``). Il consomme un itérable de
   LogEntry et rend un générateur : rien n'est chargé entièrement en RAM.

2. Audit de contexte : ``audit_scope`` / ``audit_runtime`` inspectent
   ``globals()`` et ``locals()`` et produisent un rapport des variables
   chargées en mémoire, exportable en JSON.

Entrée attendue : les TransformedEntry du module 2 (voir « Contrat » du
README) : timestamp (datetime), level (MAJ), ip, user (min), payload
(dict ou str), meta (ip, port, protocole), summary, channel, target.
Sortie : le même dict, copié, plus une clé ``"alerts"`` (tuple de str).
``meta`` n'est jamais modifié.

Une règle est une fonction ``rule(entry, **config) -> str | None`` :
elle renvoie un libellé d'alerte si l'entrée est suspecte, sinon ``None``.
Chaque règle ne lit que les clés de config qui la concernent et ignore
le reste grâce à ``**_``.
"""

from __future__ import annotations

import json
import sys
import types
from datetime import datetime
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # pour le typage uniquement : aucun import réel au runtime
    from log_engine.transform import TransformedEntry

# Les règles lisent n'importe quel dict conforme au contrat (TransformedEntry).
LogEntry = Mapping[str, Any]
Rule = Callable[..., Optional[str]]

DEFAULT_ALERT_LEVELS: frozenset[str] = frozenset({"ERROR", "CRITICAL"})
DEFAULT_PATTERNS: tuple[str, ...] = (
    "' or 1=1",
    "union select",
    "../",
    "<script",
    "/etc/passwd",
)
DEFAULT_WORK_HOURS: tuple[int, int] = (8, 20)
DEFAULT_SENSITIVE_PORTS: frozenset[int] = frozenset({22, 23, 3389, 5900})
RULE_PREFIX = "rule_"


# ---------------------------------------------------------------------------
# Règles de sécurité (fonctions de première classe)
# ---------------------------------------------------------------------------

def rule_severity(entry: LogEntry, **config: Any) -> Optional[str]:
    """Alerte si le niveau fait partie des niveaux surveillés."""
    levels = config.get("alert_levels", DEFAULT_ALERT_LEVELS)
    level = str(entry.get("level", "")).upper()
    return f"severity:{level}" if level in levels else None


def rule_blacklisted_ip(entry: LogEntry, **config: Any) -> Optional[str]:
    """Alerte si l'IP source est dans la blacklist (frozenset)."""
    blacklist = config.get("blacklist", frozenset())
    ip = entry.get("ip")
    return f"blacklisted_ip:{ip}" if ip in blacklist else None


def rule_auth_failure(entry: LogEntry, **_: Any) -> Optional[str]:
    """Alerte sur chaque échec d'authentification (canal du module 2)."""
    if entry.get("channel") == "auth_failure":
        return f"auth_failure:{entry.get('ip')}"
    return None


def rule_sensitive_port(entry: LogEntry, **config: Any) -> Optional[str]:
    """Alerte sur un accès à un port d'administration (lu dans ``meta``).

    ``meta`` est un tuple immuable (ip, port, protocole) : on le dépaquette
    en lecture seule, sans jamais le modifier.
    """
    ports = config.get("sensitive_ports", DEFAULT_SENSITIVE_PORTS)
    meta = entry.get("meta")
    if not (isinstance(meta, tuple) and len(meta) == 3):
        return None
    _, port, protocol = meta
    return f"sensitive_port:{port}/{protocol}" if port in ports else None


def rule_suspicious_payload(entry: LogEntry, **config: Any) -> Optional[str]:
    """Alerte si le payload contient un motif d'injection connu."""
    patterns = config.get("patterns", DEFAULT_PATTERNS)
    payload = entry.get("payload")
    if payload is None:
        return None
    text = (json.dumps(payload) if not isinstance(payload, str)
            else payload).lower()
    hits = [p for p in patterns if p in text]
    return f"suspicious_payload:{hits[0]}" if hits else None


def rule_off_hours(entry: LogEntry, **config: Any) -> Optional[str]:
    """Alerte si l'événement a lieu hors des heures ouvrées."""
    start, end = config.get("work_hours", DEFAULT_WORK_HOURS)
    raw = entry.get("timestamp")
    if isinstance(raw, datetime):
        stamp = raw
    else:
        try:
            stamp = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return None  # horodatage illisible : la règle ne se prononce pas
    return None if start <= stamp.hour < end else f"off_hours:{stamp:%H:%M}"


# ---------------------------------------------------------------------------
# Moteur de règles
# ---------------------------------------------------------------------------

def discover_rules(namespace: Optional[Mapping[str, Any]] = None,
                   prefix: str = RULE_PREFIX) -> tuple[Rule, ...]:
    """Découvre dynamiquement les règles via ``globals()``.

    Toute fonction dont le nom commence par ``prefix`` est une règle.
    On peut passer un autre espace de noms (ex. ``globals()`` de main.py)
    pour y découvrir des règles ajoutées ailleurs.
    """
    scope = globals() if namespace is None else namespace
    return tuple(
        obj for name, obj in sorted(scope.items())
        if name.startswith(prefix) and callable(obj)
    )


def apply_security_rules(*args: Rule,
                         **kwargs: Any) -> Iterator[TransformedEntry]:
    """Applique les règles reçues en ``*args`` à chaque entrée.

    Arguments nommés reconnus (le reste est transmis tel quel aux règles) :
        entries      : itérable de LogEntry (obligatoire).
        only_alerts  : si True, ne rend que les entrées avec au moins
                       une alerte (défaut False).
        strict       : si True, une règle qui lève une exception arrête
                       le pipeline ; sinon l'erreur est notée dans les
                       alertes et on continue (défaut False).

    Sans règle passée en ``*args``, toutes les règles ``rule_*`` du
    module sont utilisées.

    Rend un générateur de nouveaux dicts (l'entrée d'origine n'est pas
    modifiée) enrichis d'une clé ``"alerts"`` (tuple de libellés).
    """
    if "entries" not in kwargs:
        raise TypeError("apply_security_rules() requiert entries=<itérable>")
    entries: Iterable[LogEntry] = kwargs.pop("entries")
    only_alerts: bool = kwargs.pop("only_alerts", False)
    strict: bool = kwargs.pop("strict", False)
    config = kwargs  # ce qui reste = configuration dynamique des règles

    not_callable = [repr(a) for a in args if not callable(a)]
    if not_callable:
        raise TypeError(f"Règles non appelables : {', '.join(not_callable)}")
    rules = args or discover_rules()

    return _run_rules(entries, rules, config, only_alerts, strict)


def _run_rules(entries: Iterable[LogEntry], rules: tuple[Rule, ...],
               config: Mapping[str, Any], only_alerts: bool,
               strict: bool) -> Iterator[TransformedEntry]:
    """Générateur interne : séparé pour que les erreurs d'arguments
    soient levées dès l'appel, et non au premier ``next()``."""
    for entry in entries:
        if entry is None:
            continue
        alerts = []
        for rule in rules:
            try:
                result = rule(entry, **config)
            except Exception as exc:  # une règle buggée ne casse pas tout
                if strict:
                    raise
                alerts.append(
                    f"rule_error:{rule.__name__}:{type(exc).__name__}")
            else:
                if result:
                    alerts.append(result)
        if only_alerts and not alerts:
            continue
        yield {**entry, "alerts": tuple(alerts)}


# ---------------------------------------------------------------------------
# Audit d'introspection : globals() / locals()
# ---------------------------------------------------------------------------

def _kind(value: Any) -> str:
    """Classe une variable pour le rapport."""
    if isinstance(value, types.ModuleType):
        return "module"
    if isinstance(value, type):
        return "class"
    if callable(value):
        return "function"
    return "variable"


def _preview(value: Any, limit: int = 60) -> str:
    """repr tronqué ; ne consomme jamais un générateur."""
    try:
        text = repr(value)
    except Exception as exc:  # repr peut échouer sur des objets exotiques
        text = f"<repr impossible : {type(exc).__name__}>"
    return text if len(text) <= limit else text[: limit - 3] + "..."


def audit_scope(namespace: Mapping[str, Any], scope_name: str,
                include_private: bool = False) -> dict[str, Any]:
    """Construit le rapport d'audit d'un espace de noms.

    ``namespace`` est typiquement le résultat de ``globals()`` ou
    ``locals()``. On travaille sur une copie pour ne pas être gêné si
    l'espace de noms change pendant l'inspection.
    """
    snapshot = dict(namespace)
    variables = []
    for name, value in sorted(snapshot.items()):
        if not include_private and name.startswith("_"):
            continue
        variables.append({
            "name": name,
            "kind": _kind(value),
            "type": type(value).__name__,
            "size_bytes": sys.getsizeof(value),
            "preview": _preview(value),
        })
    counts: dict[str, int] = {}
    for var in variables:
        counts[var["kind"]] = counts.get(var["kind"], 0) + 1
    return {
        "scope": scope_name,
        "total": len(variables),
        "by_kind": counts,
        "total_size_bytes": sum(v["size_bytes"] for v in variables),
        "variables": variables,
    }


def audit_runtime(global_ns: Optional[Mapping[str, Any]] = None,
                  local_ns: Optional[Mapping[str, Any]] = None,
                  include_private: bool = False) -> dict[str, Any]:
    """Rapport complet sur la portée globale et la portée locale.

    Depuis main.py : ``audit_runtime(globals(), locals())``.
    Sans argument : audite les globals() de ce module et les locals()
    de cette fonction.
    """
    if global_ns is None:
        global_ns = globals()
    if local_ns is None:
        local_ns = locals()
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "python": sys.version.split()[0],
        "globals": audit_scope(global_ns, "globals", include_private),
        "locals": audit_scope(local_ns, "locals", include_private),
    }


def export_audit_report(report: Mapping[str, Any],
                        path: str | Path) -> Path:
    """Écrit le rapport d'audit en JSON et renvoie le chemin."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
    return target


def format_audit_report(report: Mapping[str, Any]) -> str:
    """Résumé texte du rapport, pour l'affichage dans main.py."""
    lines = [f"Audit du {report['generated_at']} (Python {report['python']})"]
    for key in ("globals", "locals"):
        scope = report[key]
        kinds = ", ".join(
            f"{k}={v}" for k, v in sorted(scope["by_kind"].items())
        )
        lines.append(f"  {key:<8}: {scope['total']} noms ({kinds}), "
                     f"{scope['total_size_bytes']} octets")
    return "\n".join(lines)
