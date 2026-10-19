import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import update_trackers as ut


class TestNormalize(unittest.TestCase):
    def test_normalize_lowercases_scheme_and_host(self):
        self.assertEqual(
            ut.normalize("UDP://Tracker.Example.COM:80/Announce"),
            "udp://tracker.example.com:80/Announce",
        )

    def test_reject_malformed_urls(self):
        self.assertIsNone(ut.normalize("javascript:alert(1)"))
        self.assertIsNone(ut.normalize("udp://bad host:80/announce"))
        self.assertIsNone(ut.normalize("udp://tracker.example.com:80/ann\x00ounce"))
        self.assertIsNone(ut.normalize("udp://tracker.example.com:80/announce" + "x" * 2000))
        self.assertIsNone(ut.normalize("udp:///announce"))
        self.assertIsNone(ut.normalize("udp://user:pass@tracker.example.com/announce"))


class TestClassify(unittest.TestCase):
    def test_classify_by_source_and_host(self):
        self.assertEqual(ut.parse_entry("udp://tracker.x.i2p:80/announce", "i2p").kind, ut.Kind.I2P)
        self.assertEqual(
            ut.parse_entry("udp://[200:1:2::3]:80/announce", "yggdrasil").kind, ut.Kind.YGGDRASIL
        )
        self.assertEqual(ut.parse_entry("udp://1.2.3.4:80/announce", "best").kind, ut.Kind.IP_LITERAL)
        self.assertEqual(ut.parse_entry("ws://tracker.example.com/announce", "best").kind, ut.Kind.WS)
        self.assertEqual(
            ut.parse_entry("udp://tracker.example.com:80/announce", "best").kind, ut.Kind.NORMAL
        )

    def test_parse_entry_malformed_returns_none(self):
        self.assertIsNone(ut.parse_entry("ftp://tracker.example.com/announce", "best"))


class TestDedupe(unittest.TestCase):
    def test_dedupe_same_host_keeps_preferred(self):
        urls = [
            "http://t.example.com:80/announce",
            "https://t.example.com/announce",
            "ws://t.example.com/announce",
            "udp://t.example.com/announce",
        ]
        entries = [ut.parse_entry(u, "best") for u in urls]

        def boom(h):
            raise OSError("no dns")

        out = ut.dedupe(entries, resolve=boom)
        self.assertEqual([e.url for e in out], ["udp://t.example.com/announce"])

    def test_dedupe_without_dns(self):
        def boom(h):
            raise OSError("dns down")

        a = ut.parse_entry("udp://t.example.com:80/announce", "best")
        b = ut.parse_entry("https://t.example.com/announce", "all_ip")
        out = ut.dedupe([a, b], resolve=boom)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].url, "udp://t.example.com:80/announce")

    def test_dedupe_ip_literal_prefers_domain_version(self):
        domain = ut.parse_entry("udp://tracker.example.com:6969/announce", "best")
        literal = ut.parse_entry("udp://9.9.9.9:6969/announce", "all_ip")
        out = ut.dedupe([literal, domain], resolve=lambda h: ["9.9.9.9"])
        self.assertEqual([e.url for e in out], ["udp://tracker.example.com:6969/announce"])

    def test_dedupe_merges_sources(self):
        a = ut.parse_entry("udp://t.example.com:80/announce", "best")
        b = ut.parse_entry("udp://t.example.com:80/announce", "all_ip")
        out = ut.dedupe([a, b], resolve=lambda h: [])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].sources, {"best", "all_ip"})


BLACKLIST_TEXT = """\
# comment line
tracker.bad.com
*.bad2.com
203.0.113.0/24
keyword:spamtest
"""


class TestBlacklist(unittest.TestCase):
    def _load(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(BLACKLIST_TEXT)
            p = Path(f.name)
        try:
            return ut.load_blacklist(p)
        finally:
            p.unlink()

    def test_blacklist_exact_suffix_ip_keyword(self):
        bl = self._load()
        self.assertTrue(ut.is_blocked(ut.parse_entry("udp://tracker.bad.com:80/announce", "best"), [], bl))
        self.assertTrue(ut.is_blocked(ut.parse_entry("udp://x.bad2.com:80/announce", "best"), [], bl))
        self.assertTrue(
            ut.is_blocked(ut.parse_entry("udp://tracker.example.com:80/announce", "best"), ["203.0.113.7"], bl)
        )
        self.assertTrue(
            ut.is_blocked(ut.parse_entry("udp://spamtest.example.com:80/announce", "best"), [], bl)
        )

    def test_yggdrasil_not_killed_by_private_rules(self):
        bl = ut.Blacklist(hosts=set(), suffixes=set(), ips=set(), keywords=set())
        e = ut.parse_entry("udp://[200:1122:3344::1]:80/announce", "yggdrasil")
        self.assertFalse(ut.is_blocked(e, ["200:1122:3344::1"], bl))
        e_ula = ut.parse_entry("udp://[fd00::1]:80/announce", "yggdrasil")
        self.assertFalse(ut.is_blocked(e_ula, ["fd00::1"], bl))
        e_private = ut.parse_entry("udp://10.0.0.1:80/announce", "all_ip")
        self.assertTrue(ut.is_blocked(e_private, ["10.0.0.1"], bl))

    def test_vulgar_keyword_blocked(self):
        bl = ut.Blacklist(hosts=set(), suffixes=set(), ips=set(), keywords=set())
        e = ut.parse_entry("udp://casino-tracker.example.com:80/announce", "best")
        self.assertTrue(ut.is_blocked(e, [], bl))


class TestSources(unittest.TestCase):
    def test_sources_five_urls(self):
        self.assertEqual(set(ut.SOURCES), {"best", "i2p", "yggdrasil", "all_ip", "yggdrasil_ip"})
        self.assertEqual(
            ut.SOURCES["best"],
            "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt",
        )
        self.assertEqual(
            ut.SOURCES["i2p"],
            "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_i2p.txt",
        )
        self.assertEqual(
            ut.SOURCES["yggdrasil"],
            "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_yggdrasil.txt",
        )
        self.assertEqual(
            ut.SOURCES["all_ip"],
            "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ip.txt",
        )
        self.assertEqual(
            ut.SOURCES["yggdrasil_ip"],
            "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_yggdrasil_ip.txt",
        )


if __name__ == "__main__":
    unittest.main()


class TestProbes(unittest.TestCase):
    def test_probe_udp_fails_fast_on_closed_port(self):
        import asyncio
        import time

        t0 = time.perf_counter()
        result = asyncio.run(ut.probe_udp("udp://127.0.0.1:1/announce", timeout=2.0))
        elapsed = time.perf_counter() - t0
        self.assertFalse(result.ok)
        self.assertLess(elapsed, 5.0)

    def test_probe_http_ok_with_local_server(self):
        import asyncio
        import http.server
        import threading

        body = b"d8:intervali1800e5:peers0:e"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = asyncio.run(ut.probe_http(f"http://127.0.0.1:{port}/announce", timeout=5.0))
        finally:
            server.shutdown()
            server.server_close()
        self.assertTrue(result.ok)
        self.assertIsNotNone(result.rtt_ms)

    def test_probe_http_failure_reason_is_not_alive(self):
        import asyncio
        import http.server
        import threading

        body = b"d14:failure reason12:not allowed!e"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = asyncio.run(ut.probe_http(f"http://127.0.0.1:{port}/announce", timeout=5.0))
        finally:
            server.shutdown()
            server.server_close()
        self.assertFalse(result.ok)

    def test_probe_all_aggregates_rounds(self):
        import asyncio
        import http.server
        import threading

        body = b"d8:intervali1800e5:peers0:e"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            results = asyncio.run(
                ut.probe_all([f"http://127.0.0.1:{port}/announce"], rounds=3, concurrency=4)
            )
        finally:
            server.shutdown()
            server.server_close()
        (result,) = results.values()
        self.assertEqual(result.attempts, 3)
        self.assertEqual(result.success_rate, 1.0)
        self.assertTrue(result.ok)


class TestScore(unittest.TestCase):
    def _probe(self, url="u", ok=True, rtt_ms=100.0, success_rate=1.0):
        return ut.ProbeResult(
            url=url, ok=ok, rtt_ms=rtt_ms, success_rate=success_rate, attempts=3, detail=""
        )

    def test_score_faster_ranks_higher(self):
        fast = self._probe(rtt_ms=100.0)
        slow = self._probe(rtt_ms=300.0)
        self.assertGreater(
            ut.score(fast, None, 1, ut.Kind.NORMAL),
            ut.score(slow, None, 1, ut.Kind.NORMAL),
        )

    def test_score_falls_back_to_history_when_all_probes_fail(self):
        dead = self._probe(ok=False, rtt_ms=None, success_rate=0.0)
        history = {"u": {"score": 0.8, "rtt_ms": 100.0, "success_rate": 1.0, "in_best": True}}
        self.assertAlmostEqual(ut.score(dead, history, 1, ut.Kind.NORMAL), 0.8 * 0.9)

    def test_score_penalizes_ip_literal(self):
        normal = self._probe()
        literal = self._probe()
        self.assertGreater(
            ut.score(normal, None, 1, ut.Kind.NORMAL),
            ut.score(literal, None, 1, ut.Kind.IP_LITERAL),
        )

    def test_apply_udp_history_fallback_when_udp_blocked(self):
        history = {
            "udp://t.example.com:80/announce": {
                "score": 0.8,
                "rtt_ms": 120.0,
                "success_rate": 1.0,
                "in_best": True,
            }
        }
        results = {
            "udp://t.example.com:80/announce": ut.ProbeResult(
                url="udp://t.example.com:80/announce",
                ok=False,
                rtt_ms=None,
                success_rate=0.0,
                attempts=3,
                detail="udp-fail",
            ),
            "http://h.example.com/announce": self._probe(url="http://h.example.com/announce"),
        }
        revived, udp_blocked = ut.apply_udp_history(results, history)
        self.assertTrue(udp_blocked)
        r = revived["udp://t.example.com:80/announce"]
        self.assertTrue(r.ok)
        self.assertEqual(r.rtt_ms, 120.0)
        self.assertAlmostEqual(r.success_rate, 0.9)


class TestOutputs(unittest.TestCase):
    def test_select_best_orders_fast_first(self):
        scores = {f"u{i:02d}": i / 50.0 for i in range(50)}
        best = ut.select_best(scores, 49)
        self.assertEqual(len(best), 49)
        for a, b in zip(best, best[1:]):
            self.assertGreater(scores[a], scores[b])

    def test_select_best_fewer_than_n_alive(self):
        scores = {f"u{i:02d}": i / 50.0 for i in range(40)}
        best = ut.select_best(scores, 49)
        self.assertEqual(len(best), 40)

    def test_write_list_format(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "out.txt"
            ut.write_list(p, ["udp://a/announce", "udp://b/announce"])
            self.assertEqual(p.read_text(encoding="utf-8"), "udp://a/announce\nudp://b/announce\n")
            empty = Path(td) / "empty.txt"
            ut.write_list(empty, [])
            self.assertEqual(empty.read_text(encoding="utf-8"), "")

    def test_needs_commit(self):
        a = {"trackers_best.txt": "aaa", "stats.json": '{"generated_at": "t1"}'}
        b = {"trackers_best.txt": "aaa", "stats.json": '{"generated_at": "t1"}'}
        self.assertFalse(ut.needs_commit(a, b))
        c = {"trackers_best.txt": "aaa", "stats.json": '{"generated_at": "t2"}'}
        self.assertTrue(ut.needs_commit(a, c))


class TestReadme(unittest.TestCase):
    def test_update_readme_only_touches_markers(self):
        text = (
            "# 标题\n中文前文\n"
            "<!-- META:START -->\n旧徽章\n<!-- META:END -->\n中间段\n"
            "<!-- LEADERBOARD:START -->\n旧榜\n<!-- LEADERBOARD:END -->\n后文尾巴\n"
        )
        rows = [
            {
                "rank": 1,
                "url": "udp://t.example.com:80/announce",
                "scheme": "udp",
                "median_ms": 12.5,
                "success_rate": 1.0,
                "score": 0.91,
            }
        ]
        meta = {"updated": "2026-10-19", "selected": 49}
        out = ut.update_readme(text, rows, meta)
        self.assertTrue(out.startswith(text.split("<!-- META:START -->")[0]))
        self.assertTrue(out.endswith(text.split("<!-- LEADERBOARD:END -->")[1]))
        self.assertIn("中文前文", out)
        self.assertIn("中间段", out)
        self.assertNotIn("旧榜", out)
        self.assertIn("udp://t.example.com:80/announce", out)
        self.assertIn("2026--10--19", out)


class TestMainAbort(unittest.TestCase):
    def test_abort_when_alive_below_floor(self):
        import asyncio
        import tempfile
        from unittest import mock

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            src.mkdir()
            (src / "best.txt").write_text(
                "\n".join(f"udp://t{i}.example.com:80/announce" for i in range(20)),
                encoding="utf-8",
            )
            keep = "udp://keep.me:80/announce\n"
            (root / "trackers_best.txt").write_text(keep, encoding="utf-8")

            async def fake_probe_all(urls, rounds=3, concurrency=32):
                return {
                    u: ut.ProbeResult(
                        url=u, ok=True, rtt_ms=50.0, success_rate=1.0, attempts=rounds, detail="ok"
                    )
                    for u in urls
                }

            with mock.patch.object(ut, "probe_all", fake_probe_all), mock.patch.object(
                ut, "resolve_host", lambda h: []
            ):
                rc = ut.main(["--source-dir", str(src), "--root", str(root)])

            self.assertEqual(rc, 2)
            self.assertEqual((root / "trackers_best.txt").read_text(encoding="utf-8"), keep)
