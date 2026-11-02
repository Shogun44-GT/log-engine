import tracemalloc
import unittest
from datetime import datetime
from pathlib import Path
from types import GeneratorType

from log_engine.ingestion import (
    parse_line,
    parse_logs,
    read_logs,
    read_multiple_logs,
)

DATA = Path(__file__).resolve().parent.parent / "data"
FILE_A = DATA / "server_a.log"
FILE_B = DATA / "server_b.log"

VALID = (
    '2026-11-03T08:00:01 | INFO | 192.168.1.10:443/TCP | alice | '
    '{"action": "login", "status": "success"}'
)


class TestReadLogs(unittest.TestCase):
    def test_is_generator(self):
        self.assertIsInstance(read_logs(FILE_A), GeneratorType)

    def test_skips_empty_lines(self):
        lines = list(read_logs(FILE_A))
        self.assertEqual(len(lines), 10)
        self.assertTrue(all(line.strip() for line in lines))

    def test_no_trailing_newline(self):
        first = next(read_logs(FILE_A))
        self.assertFalse(first.endswith("\n"))

    def test_lazy(self):
        gen = read_logs(FILE_A)
        self.assertTrue(next(gen).startswith("2026-11-03T08:00:01"))
        gen.close()

    def test_constant_memory_on_big_file(self):
        big = DATA / "_big_test.log"
        try:
            with open(big, "w", encoding="utf-8") as handle:
                for _ in range(200_000):
                    handle.write(VALID + "\n")
            tracemalloc.start()
            count = sum(1 for _ in read_logs(big))
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            self.assertEqual(count, 200_000)
            self.assertLess(peak, 1_000_000)
        finally:
            big.unlink(missing_ok=True)


class TestReadMultipleLogs(unittest.TestCase):
    def test_is_generator(self):
        self.assertIsInstance(
            read_multiple_logs([FILE_A, FILE_B]), GeneratorType
        )

    def test_chains_in_order(self):
        lines = list(read_multiple_logs([FILE_A, FILE_B]))
        self.assertEqual(len(lines), 19)
        self.assertTrue(lines[0].startswith("2026-11-03T08:00:01"))
        self.assertTrue(lines[-1].startswith("2026-11-03T09:05:00"))

    def test_missing_file_is_skipped(self):
        lines = list(read_multiple_logs([FILE_A, DATA / "absent.log"]))
        self.assertEqual(len(lines), 10)


class TestParseLine(unittest.TestCase):
    def test_contract_keys_and_types(self):
        entry = parse_line(VALID)
        self.assertEqual(
            set(entry),
            {"timestamp", "level", "ip", "user", "payload", "meta"},
        )
        self.assertEqual(entry["timestamp"], datetime(2026, 11, 3, 8, 0, 1))
        self.assertEqual(entry["level"], "INFO")
        self.assertEqual(entry["ip"], "192.168.1.10")
        self.assertEqual(entry["user"], "alice")
        self.assertEqual(
            entry["payload"], {"action": "login", "status": "success"}
        )
        self.assertEqual(entry["meta"], ("192.168.1.10", 443, "TCP"))
        self.assertIsInstance(entry["meta"], tuple)

    def test_raw_payload(self):
        entry = parse_line(
            "2026-11-03T08:03:00 | INFO | 192.168.1.10:53/UDP | alice | "
            "DNS query example.com"
        )
        self.assertEqual(entry["payload"], "DNS query example.com")
        self.assertEqual(entry["meta"], ("192.168.1.10", 53, "UDP"))

    def test_broken_json_stays_raw(self):
        entry = parse_line(
            "2026-11-03T09:02:00 | WARNING | 198.51.100.4:80/HTTP | guest | "
            "{payload json cassé"
        )
        self.assertEqual(entry["payload"], "{payload json cassé")

    def test_pipes_inside_payload(self):
        entry = parse_line(
            "2026-11-03T09:03:00 | INFO | 192.168.1.12:443/TCP | dave | "
            "message | avec | des pipes"
        )
        self.assertEqual(entry["payload"], "message | avec | des pipes")

    def test_level_is_normalized(self):
        entry = parse_line(VALID.replace("INFO", "error"))
        self.assertEqual(entry["level"], "ERROR")

    def test_invalid_lines_return_none(self):
        invalid = [
            "",
            "   ",
            "ligne corrompue sans aucun séparateur",
            VALID.replace("INFO", "DEBUG"),
            VALID.replace("2026-11-03T08:00:01", "2026-13-45T99:00:00"),
            VALID.replace("443", "abc"),
            VALID.replace(":443/TCP", "/TCP"),
        ]
        for line in invalid:
            with self.subTest(line=line):
                self.assertIsNone(parse_line(line))


class TestParseLogs(unittest.TestCase):
    def test_pipeline_on_sample(self):
        entries = list(parse_logs(read_multiple_logs([FILE_A, FILE_B])))
        valid = list(filter(None, entries))
        self.assertEqual(len(entries), 19)
        self.assertEqual(len(valid), 15)


if __name__ == "__main__":
    unittest.main()
