import unittest
from datetime import datetime
from pathlib import Path

from log_engine.ingestion import parse_line, parse_logs, read_multiple_logs
from log_engine.transform import (
    filter_entries,
    normalize,
    normalize_entry,
    route,
    route_entry,
    transform,
)

DATA = Path(__file__).resolve().parent.parent / "data"
FILES = [DATA / "server_a.log", DATA / "server_b.log"]


def make_entry(**overrides):
    entry = {
        "timestamp": datetime(2026, 11, 3, 8, 1, 10),
        "level": "WARNING",
        "ip": "10.0.0.5",
        "user": "root",
        "payload": {"action": "login", "status": "failed"},
        "meta": ("10.0.0.5", 22, "TCP"),
    }
    entry.update(overrides)
    return entry


class TestFilter(unittest.TestCase):
    def test_removes_none_and_invalid(self):
        good = make_entry()
        no_user = make_entry(user="")
        no_ip = make_entry(ip="")
        result = list(filter_entries([None, good, no_user, None, no_ip]))
        self.assertEqual(result, [good])

    def test_is_lazy(self):
        result = filter_entries(iter([make_entry()]))
        self.assertFalse(isinstance(result, list))
        self.assertEqual(next(result)["user"], "root")

    def test_on_sample_files(self):
        entries = parse_logs(read_multiple_logs(FILES))
        self.assertEqual(len(list(filter_entries(entries))), 15)


class TestNormalize(unittest.TestCase):
    def test_strings_case_and_summary(self):
        entry = make_entry(
            user="  ROOT ",
            payload={" Action ": " LOGIN ", "Status": "FAILED", "Msg": " Hi "},
            meta=(" 10.0.0.5 ", 22, "tcp"),
        )
        result = normalize_entry(entry)
        self.assertEqual(result["user"], "root")
        self.assertEqual(
            result["payload"],
            {"action": "login", "status": "failed", "msg": "Hi"},
        )
        self.assertEqual(result["meta"], ("10.0.0.5", 22, "TCP"))
        self.assertEqual(
            result["summary"],
            "[2026-11-03 08:01:10] WARNING  root@10.0.0.5:22/TCP",
        )

    def test_raw_payload_whitespace(self):
        result = normalize_entry(make_entry(payload="  DNS   query \t x  "))
        self.assertEqual(result["payload"], "DNS query x")

    def test_does_not_mutate_input(self):
        entry = make_entry(user="ROOT")
        normalize_entry(entry)
        self.assertEqual(entry["user"], "ROOT")

    def test_map_is_lazy(self):
        result = normalize(iter([make_entry()]))
        self.assertEqual(next(result)["user"], "root")


class TestRoute(unittest.TestCase):
    def test_raw_string(self):
        self.assertEqual(route("DNS query"), ("raw", "DNS query"))

    def test_error_dict(self):
        record = {"level": "ERROR", "code": 500}
        self.assertEqual(route(record), ("error", "ERROR 500"))

    def test_critical_dict(self):
        record = {"level": "CRITICAL", "code": 1045, "message": "x"}
        self.assertEqual(route(record), ("error", "CRITICAL 1045"))

    def test_auth_failure_dict(self):
        record = {"action": "login", "status": "failed"}
        self.assertEqual(route(record)[0], "auth_failure")

    def test_auth_success_dict(self):
        record = {"action": "login", "status": "success"}
        self.assertEqual(route(record), ("auth", "login success"))

    def test_other_dict(self):
        self.assertEqual(route({"action": "logout"})[0], "event")

    def test_connection_tuple(self):
        record = ("10.0.0.5", 22, "TCP")
        self.assertEqual(route(record), ("connection", "10.0.0.5:22/TCP"))

    def test_unknown(self):
        for record in ("", "   ", 42, None, ("ip", "22", "TCP")):
            with self.subTest(record=record):
                self.assertEqual(route(record)[0], "unknown")

    def test_route_entry_merges_level(self):
        entry = make_entry(level="ERROR", payload={"code": 500})
        result = route_entry(entry)
        self.assertEqual(result["channel"], "error")
        self.assertEqual(result["target"], "10.0.0.5:22/TCP")


class TestTransformPipeline(unittest.TestCase):
    def test_full_chain_on_sample(self):
        result = list(transform(parse_logs(read_multiple_logs(FILES))))
        self.assertEqual(len(result), 15)
        channels = [entry["channel"] for entry in result]
        self.assertEqual(channels.count("auth_failure"), 5)
        self.assertEqual(channels.count("error"), 3)
        self.assertEqual(channels.count("raw"), 3)

    def test_line_with_lowercase_level(self):
        line = (
            "2026-11-03T09:01:05 | error | 203.0.113.7:3306/TCP | ADMIN | "
            '{"code": 1045, "message": "Access denied"}'
        )
        result = next(transform([parse_line(line)]))
        self.assertEqual(result["user"], "admin")
        self.assertEqual(result["channel"], "error")


if __name__ == "__main__":
    unittest.main()
