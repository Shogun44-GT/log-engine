"""Tests du module 4 (log_engine/rules.py). Lancer : python -m unittest -v"""

import inspect
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from log_engine import rules
from log_engine.rules import (
    apply_security_rules,
    audit_runtime,
    audit_scope,
    discover_rules,
    export_audit_report,
    format_audit_report,
    rule_auth_failure,
    rule_blacklisted_ip,
    rule_off_hours,
    rule_sensitive_port,
    rule_severity,
    rule_suspicious_payload,
)

BLACKLIST = frozenset({"10.0.0.5", "192.168.1.66"})
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

try:  # modules 1 et 2, pour le test d'intégration
    from log_engine.ingestion import parse_logs, read_multiple_logs
    from log_engine.transform import transform
    PIPELINE_OK = True
except ImportError:
    PIPELINE_OK = False


def make_entry(**overrides):
    """TransformedEntry conforme au contrat du README."""
    ip = overrides.pop("ip", "192.168.1.10")
    port = overrides.pop("port", 443)
    base = {
        "timestamp": datetime(2026, 11, 3, 10, 15, 0),
        "level": "INFO",
        "ip": ip,
        "user": "alice",
        "payload": "GET /index.html",
        "meta": (ip, port, "TCP"),
        "summary": f"[2026-11-03 10:15:00] INFO  alice@{ip}:{port}/TCP",
        "channel": "event",
        "target": f"{ip}:{port}/TCP",
    }
    base.update(overrides)
    return base


class TestRegles(unittest.TestCase):

    def test_severity_alerte_sur_error(self):
        self.assertEqual(
            rule_severity(make_entry(level="error")), "severity:ERROR"
        )

    def test_severity_ignore_info(self):
        self.assertIsNone(rule_severity(make_entry()))

    def test_severity_niveaux_configurables(self):
        self.assertIsNotNone(
            rule_severity(
                make_entry(level="WARNING"), alert_levels={"WARNING"}
            )
        )

    def test_blacklist(self):
        entry = make_entry(ip="10.0.0.5")
        self.assertEqual(rule_blacklisted_ip(entry, blacklist=BLACKLIST),
                         "blacklisted_ip:10.0.0.5")
        self.assertIsNone(rule_blacklisted_ip(entry))

    def test_auth_failure(self):
        self.assertIsNotNone(
            rule_auth_failure(make_entry(channel="auth_failure"))
        )
        self.assertIsNone(rule_auth_failure(make_entry()))

    def test_payload_str_et_dict(self):
        self.assertIsNotNone(rule_suspicious_payload(
            make_entry(payload="id=1' OR 1=1 --")))
        self.assertIsNotNone(rule_suspicious_payload(
            make_entry(payload={"path": "../../etc/passwd"})))
        self.assertIsNone(rule_suspicious_payload(make_entry(payload=None)))

    def test_sensitive_port_lit_meta(self):
        entry = make_entry(port=22)
        self.assertEqual(rule_sensitive_port(entry), "sensitive_port:22/TCP")
        self.assertIsNone(rule_sensitive_port(make_entry()))
        self.assertIsNone(rule_sensitive_port(make_entry(meta=None)))

    def test_off_hours(self):
        night = make_entry(timestamp=datetime(2026, 11, 3, 3, 12))
        self.assertEqual(rule_off_hours(night), "off_hours:03:12")
        late = make_entry(timestamp="2026-11-04T23:05:00")
        self.assertEqual(rule_off_hours(late), "off_hours:23:05")
        self.assertIsNone(rule_off_hours(make_entry()))
        self.assertIsNone(rule_off_hours(make_entry(timestamp="pas une date")))


class TestMoteur(unittest.TestCase):

    def test_rend_un_generateur(self):
        result = apply_security_rules(rule_severity, entries=[make_entry()])
        self.assertTrue(inspect.isgenerator(result))

    def test_paresseux_sur_flux_infini(self):
        def infini():
            while True:
                yield make_entry(level="ERROR")
        gen = apply_security_rules(rule_severity, entries=infini())
        self.assertEqual(next(gen)["alerts"], ("severity:ERROR",))

    def test_kwargs_transmis_aux_regles(self):
        out = list(apply_security_rules(
            rule_blacklisted_ip, rule_severity,
            entries=[make_entry(ip="10.0.0.5", level="CRITICAL")],
            blacklist=BLACKLIST))
        self.assertEqual(out[0]["alerts"],
                         ("blacklisted_ip:10.0.0.5", "severity:CRITICAL"))

    def test_entree_non_modifiee_et_meta_conserve(self):
        entry = make_entry(level="ERROR")
        out = next(apply_security_rules(rule_severity, entries=[entry]))
        self.assertNotIn("alerts", entry)
        self.assertIs(out["meta"], entry["meta"])
        self.assertEqual(out["channel"], "event")

    def test_only_alerts_et_none_ignores(self):
        data = [make_entry(), None, make_entry(level="ERROR")]
        out = list(
            apply_security_rules(rule_severity, entries=data, only_alerts=True)
        )
        self.assertEqual(len(out), 1)

    def test_regle_lambda_acceptee(self):
        def admin(e, **_):
            return "admin" if e.get("user") == "root" else None

        entries = [make_entry(user="root")]
        out = list(apply_security_rules(admin, entries=entries))
        self.assertEqual(out[0]["alerts"], ("admin",))

    def test_sans_regle_utilise_toutes_les_regles(self):
        out = list(apply_security_rules(
            entries=[make_entry(level="ERROR", channel="auth_failure")]))
        self.assertIn("severity:ERROR", out[0]["alerts"])
        self.assertIn("auth_failure:192.168.1.10", out[0]["alerts"])

    def test_regle_qui_plante(self):
        def boom(entry, **_):
            raise KeyError("x")
        out = list(apply_security_rules(boom, entries=[make_entry()]))
        self.assertEqual(out[0]["alerts"], ("rule_error:boom:KeyError",))
        with self.assertRaises(KeyError):
            list(
                apply_security_rules(boom, entries=[make_entry()], strict=True)
            )

    def test_erreurs_d_arguments_immediates(self):
        with self.assertRaises(TypeError):
            apply_security_rules(rule_severity)  # pas d'entries
        with self.assertRaises(TypeError):
            apply_security_rules("pas une fonction", entries=[])

    def test_brute_force_donnees_de_test(self):
        """Les 5 échecs sur 10.0.0.5 doivent tous ressortir."""
        data = [
            make_entry(ip="10.0.0.5", channel="auth_failure")
            for _ in range(5)
        ]
        data += [make_entry() for _ in range(10)]
        out = list(apply_security_rules(rule_auth_failure, entries=data,
                                        only_alerts=True))
        self.assertEqual(len(out), 5)


class TestIntrospection(unittest.TestCase):

    def test_discover_rules_via_globals(self):
        names = {f.__name__ for f in discover_rules()}
        expected = {
            "rule_severity", "rule_blacklisted_ip", "rule_auth_failure",
            "rule_suspicious_payload", "rule_off_hours", "rule_sensitive_port",
        }
        self.assertEqual(names, expected)

    def test_discover_rules_espace_externe(self):
        ns = {"rule_custom": lambda e, **_: None, "autre": 42}
        self.assertEqual(len(discover_rules(ns)), 1)

    def test_audit_scope_locals(self):
        compteur = 3
        nom = "audit"
        report = audit_scope(locals(), "locals")
        names = {v["name"] for v in report["variables"]}
        self.assertTrue({"compteur", "nom", "self"} <= names)
        self.assertEqual(report["total"], len(report["variables"]))

    def test_audit_ne_consomme_pas_les_generateurs(self):
        gen = (i for i in range(3))
        audit_scope({"gen": gen}, "locals")
        self.assertEqual(next(gen), 0)

    def test_audit_prive_masque_par_defaut(self):
        report = audit_scope({"_secret": 1, "public": 2}, "x")
        self.assertEqual([v["name"] for v in report["variables"]], ["public"])

    def test_audit_runtime_globals_du_module(self):
        report = audit_runtime()
        names = {v["name"] for v in report["globals"]["variables"]}
        self.assertIn("apply_security_rules", names)
        self.assertGreater(report["globals"]["by_kind"]["module"], 0)

    def test_export_json_et_format(self):
        report = audit_runtime(vars(rules), {"x": 1})
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out" / "audit.json"
            path = export_audit_report(report, target)
            loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["locals"]["total"], 1)
        self.assertIn("globals", format_audit_report(report))


@unittest.skipUnless(PIPELINE_OK and DATA_DIR.is_dir(),
                     "modules 1/2 ou data/ absents")
class TestIntegration(unittest.TestCase):
    """Bout en bout : ingestion -> transform -> rules, sur data/."""

    def test_pipeline_complet(self):
        files = [str(p) for p in sorted(DATA_DIR.glob("*.log"))]
        entries = transform(parse_logs(read_multiple_logs(files)))
        out = apply_security_rules(entries=entries, blacklist=BLACKLIST)
        self.assertTrue(inspect.isgenerator(out))
        results = list(out)
        self.assertTrue(results)
        for entry in results:
            self.assertIsInstance(entry["meta"], tuple)
            self.assertIsInstance(entry["alerts"], tuple)
        failures = [e for e in results
                    if "auth_failure:10.0.0.5" in e["alerts"]]
        self.assertGreaterEqual(len(failures), 5)


if __name__ == "__main__":
    unittest.main()
