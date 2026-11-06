import unittest
from datetime import datetime, timedelta
from pathlib import Path

from log_engine.aggregation import (
    DEFAULT_BLACKLIST,
    analyze,
    compare_with_blacklist,
    format_report,
)
from log_engine.ingestion import parse_logs, read_multiple_logs
from log_engine.transform import transform

DATA = Path(__file__).resolve().parent.parent / "data"

BASE = datetime(2026, 11, 3, 8, 0, 0)


def entry(ip="10.0.0.5", user="root", level="INFO", channel="event",
          minute=0, payload=None):
    """Une TransformedEntry minimale, avec les clés du contrat."""
    return {
        "timestamp": BASE + timedelta(minutes=minute),
        "level": level,
        "ip": ip,
        "user": user,
        "payload": payload if payload is not None else {},
        "meta": (ip, 22, "TCP"),
        "summary": f"[{BASE}] {level} {user}@{ip}",
        "channel": channel,
        "target": f"{ip}:22/TCP",
    }


def failures(ip="10.0.0.5", user="root", n=5, start=0):
    return [
        entry(ip=ip, user=user, level="WARNING",
              channel="auth_failure", minute=start + i)
        for i in range(n)
    ]


class TestCompareWithBlacklist(unittest.TestCase):
    def test_operations(self):
        cmp = compare_with_blacklist(
            {"10.0.0.5", "203.0.113.7"},
            frozenset({"203.0.113.7", "45.33.32.156"}),
        )
        self.assertEqual(cmp.union,
                         {"10.0.0.5", "203.0.113.7", "45.33.32.156"})
        self.assertEqual(cmp.intersection, {"203.0.113.7"})
        self.assertEqual(cmp.only_active, {"10.0.0.5"})
        self.assertEqual(cmp.only_blacklist, {"45.33.32.156"})
        self.assertEqual(cmp.symmetric_difference,
                         {"10.0.0.5", "45.33.32.156"})

    def test_empty_active(self):
        cmp = compare_with_blacklist(set())
        self.assertEqual(cmp.intersection, set())
        self.assertEqual(cmp.only_blacklist, set(DEFAULT_BLACKLIST))

    def test_default_blacklist_is_frozen(self):
        self.assertIsInstance(DEFAULT_BLACKLIST, frozenset)
        self.assertIn("203.0.113.7", DEFAULT_BLACKLIST)


class TestAnalyzeCounters(unittest.TestCase):
    def test_counts_and_sets(self):
        entries = [
            entry(ip="192.168.1.10", user="alice", level="INFO",
                  channel="auth", minute=0),
            entry(ip="192.168.1.10", user="alice", level="ERROR",
                  channel="error", minute=1),
            entry(ip="10.0.0.5", user="root", level="CRITICAL",
                  channel="auth_failure", minute=2),
        ]
        rep = analyze(entries)
        self.assertEqual(rep.entries_scanned, 3)
        self.assertTrue(rep.completed)
        self.assertEqual(rep.by_channel,
                         {"auth": 1, "error": 1, "auth_failure": 1})
        self.assertEqual(rep.by_user, {"alice": 2, "root": 1})
        self.assertEqual(rep.by_level,
                         {"INFO": 1, "ERROR": 1, "CRITICAL": 1})
        self.assertEqual(rep.error_ips, {"192.168.1.10", "10.0.0.5"})
        self.assertEqual(rep.active_ips, {"192.168.1.10", "10.0.0.5"})

    def test_empty_stream(self):
        rep = analyze([])
        self.assertEqual(rep.entries_scanned, 0)
        self.assertTrue(rep.completed)
        self.assertEqual(rep.by_channel, {})
        self.assertEqual(rep.alerts, [])

    def test_warning_is_not_an_error_ip(self):
        rep = analyze([entry(level="WARNING", channel="event")])
        self.assertEqual(rep.error_ips, set())


class TestBruteForce(unittest.TestCase):
    def test_alert_at_threshold(self):
        rep = analyze(failures(n=5))
        self.assertEqual(len(rep.alerts), 1)
        alert = rep.alerts[0]
        self.assertEqual(alert.ip, "10.0.0.5")
        self.assertEqual(alert.attempts, 5)
        self.assertEqual(alert.users, {"root"})
        self.assertEqual(alert.first_seen, BASE)
        self.assertEqual(alert.last_seen, BASE + timedelta(minutes=4))

    def test_no_alert_below_threshold(self):
        rep = analyze(failures(n=4))
        self.assertEqual(rep.alerts, [])

    def test_success_resets_streak(self):
        entries = failures(n=4) + [entry(channel="auth", minute=4)]
        entries += failures(n=5, start=5)
        rep = analyze(entries)
        self.assertEqual(len(rep.alerts), 1)
        self.assertEqual(rep.alerts[0].attempts, 5)

    def test_other_events_do_not_break_streak(self):
        entries = failures(n=3)
        entries.append(entry(channel="event", minute=3))
        entries += failures(n=2, start=4)
        rep = analyze(entries)
        self.assertEqual(len(rep.alerts), 1)

    def test_ips_are_independent(self):
        entries = failures(ip="10.0.0.5", n=5)
        entries += failures(ip="172.16.0.3", user="bob", n=5, start=5)
        rep = analyze(entries)
        self.assertEqual(len(rep.alerts), 2)
        self.assertEqual({a.ip for a in rep.alerts},
                         {"10.0.0.5", "172.16.0.3"})

    def test_alert_keeps_growing_after_threshold(self):
        rep = analyze(failures(n=7))
        self.assertEqual(len(rep.alerts), 1)
        self.assertEqual(rep.alerts[0].attempts, 7)


class TestEarlyStopAndChunks(unittest.TestCase):
    def test_max_alerts_stops_early(self):
        entries = failures(n=5) + failures(ip="172.16.0.3", n=5, start=5)
        rep = analyze(entries, max_alerts=1)
        self.assertFalse(rep.completed)
        self.assertEqual(len(rep.alerts), 1)
        self.assertLess(rep.entries_scanned, 10)

    def test_early_stop_is_lazy(self):
        seen = []

        def gen():
            for i in range(1000):
                seen.append(i)
                yield entry(channel="auth_failure", minute=i)

        rep = analyze(gen(), chunk_size=1, max_alerts=1)
        self.assertFalse(rep.completed)
        self.assertEqual(rep.entries_scanned, 5)
        self.assertEqual(len(seen), 5)

    def test_cycles_count_full_chunks(self):
        rep = analyze([entry(minute=i) for i in range(5)], chunk_size=2)
        self.assertEqual(rep.cycles_completed, 3)

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)

    def test_invalid_chunk_size(self):
        with self.assertRaises(ValueError):
            analyze([], chunk_size=0)


class TestFormatReport(unittest.TestCase):
    def test_report_with_alert(self):
        rep = analyze(failures(n=5))
        text = format_report(rep)
        self.assertIn("ALERTE force brute", text)
        self.assertIn("10.0.0.5", text)
        self.assertIn("5 échecs", text)

    def test_report_without_alert(self):
        rep = analyze([entry(channel="auth")])
        self.assertIn("Aucune attaque par force brute", format_report(rep))


class TestEndToEnd(unittest.TestCase):
    def test_real_logs(self):
        lines = read_multiple_logs(
            [DATA / "server_a.log", DATA / "server_b.log"])
        rep = analyze(transform(parse_logs(lines)))
        self.assertEqual(rep.entries_scanned, 15)
        self.assertTrue(rep.completed)
        self.assertEqual(len(rep.alerts), 1)
        self.assertEqual(rep.alerts[0].ip, "10.0.0.5")
        self.assertEqual(rep.alerts[0].attempts, 5)
        self.assertIn("203.0.113.7", rep.blacklist.intersection)


if __name__ == "__main__":
    unittest.main()
