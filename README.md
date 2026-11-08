# Log Engine

Engine de traitement et d'analyse de flux de logs, en Python 3.10+, stdlib uniquement.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

## Lancer

```bash
python main.py                          # tous les fichiers de data/
python main.py data/server_a.log        # un fichier précis
python main.py --audit audit.json       # exporte le rapport d'audit JSON
python -m unittest -v                   # tests
```

`main.py` pilote l'ensemble du pipeline : ingestion -> transformation
-> règles de sécurité (module 4, alertes affichées entrée par entrée)
-> agrégation (module 3, rapport : IP en erreur, compteurs, force brute)
-> audit d'introspection (globals() / locals()).

## Format d'une ligne de log

```
TIMESTAMP | LEVEL | IP:PORT/PROTOCOLE | USER | PAYLOAD
2026-11-03T08:01:10 | WARNING | 10.0.0.5:22/TCP | root | {"action": "login", "status": "failed"}
```

- `TIMESTAMP` : `YYYY-MM-DDTHH:MM:SS`
- `LEVEL` : `INFO`, `WARNING`, `ERROR`, `CRITICAL` (casse indifférente)
- `PAYLOAD` : objet JSON ou texte brut (peut contenir des `|`)

## Contrat (figé)

`parse_line(ligne)` renvoie un `LogEntry`, ou `None` si la ligne est invalide.

| Clé         | Type              | Exemple                                   |
|-------------|-------------------|-------------------------------------------|
| `timestamp` | `datetime`        | `datetime(2026, 11, 3, 8, 1, 10)`         |
| `level`     | `str`             | `"WARNING"` (toujours en majuscules)      |
| `ip`        | `str`             | `"10.0.0.5"`                              |
| `user`      | `str`             | `"root"`                                  |
| `payload`   | `dict` ou `str`   | `{"action": "login", "status": "failed"}` |
| `meta`      | `tuple[str, int, str]` | `("10.0.0.5", 22, "TCP")`            |

Règles pour tous les modules :

- On reçoit et on rend des **itérables** de `LogEntry`, jamais une `list` complète.
- `parse_logs()` laisse passer les `None` : c'est au module 2 de les retirer avec `filter(None, ...)`.
- On ne modifie pas `meta` (tuple immuable).
- Une tentative de connexion = `payload` dict avec `"action": "login"` et `"status": "success"` / `"failed"`.

```python
from log_engine.ingestion import LogEntry, parse_logs, read_multiple_logs

entries = parse_logs(read_multiple_logs(["data/server_a.log", "data/server_b.log"]))
```

## Sortie du module 2 (entrée des modules 3 et 4)

`transform(entries)` renvoie un itérable de `TransformedEntry` : le `LogEntry` nettoyé, sans `None`, plus trois clés.

| Clé       | Type  | Exemple                                         |
|-----------|-------|-------------------------------------------------|
| `summary` | `str` | `"[2026-11-03 08:01:10] WARNING  root@10.0.0.5:22/TCP"` |
| `channel` | `str` | `auth`, `auth_failure`, `error`, `event`, `raw`, `unknown` |
| `target`  | `str` | `"10.0.0.5:22/TCP"`                             |

- `user` est en minuscules, `level` en majuscules.
- Dans un payload dict, les clés sont en minuscules, et les valeurs de `action` / `status` aussi.
- Brute-force (module 3) : filtrer sur `entry["channel"] == "auth_failure"`.

```python
from log_engine.ingestion import parse_logs, read_multiple_logs
from log_engine.transform import transform

entries = transform(parse_logs(read_multiple_logs(["data/server_a.log"])))
```

## Arborescence

```
log_engine/
  ingestion.py     module 1  générateurs + parsing          (Joan)
  transform.py     module 2  filter / map / lambda / match   (Joan)
  aggregation.py   module 3  sets, defaultdict, brute-force  (Youness)
  rules.py         module 4  apply_security_rules + audit    (Mathis)
data/              jeux de logs de test
tests/             un fichier test_<module>.py par module
main.py            point d'entrée du pipeline
```

## Workflow Git

- Une branche par module : `module-3-aggregation` (Youness), `module-4-rules` (Mathis).
- Chacun ne touche que son fichier et son fichier de test.
- Pull request vers `main` dès que le module passe ses tests ; Joan merge et branche le module dans `main.py`.

## Rapport

Le rapport final est dans `notebooks/rapport.ipynb` (déjà exécuté) et
`notebooks/rapport.pdf`. Pour le relancer : `pip install notebook`,
puis `jupyter notebook notebooks/rapport.ipynb`.
