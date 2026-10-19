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
