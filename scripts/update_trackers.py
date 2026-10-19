"""Pmwiu Tracker List — tracker aggregation pipeline (stdlib only).

Stage 1 (pure logic): normalize / classify / blacklist / dedupe.
Stage 2 (network): BEP-3 / BEP-15 announce probes and multi-dim scoring.
"""

import asyncio
import hashlib
import ipaddress
import json
import os
import socket
import statistics
import struct
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable

SOURCES = {
    "best": "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt",
    "i2p": "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_i2p.txt",
    "yggdrasil": "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_yggdrasil.txt",
    "all_ip": "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ip.txt",
    "yggdrasil_ip": "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_yggdrasil_ip.txt",
}

SCHEME_RANK = {"udp": 0, "https": 1, "http": 2, "ws": 3, "wss": 4}

VULGAR_KEYWORDS = ("porn", "xxx", "casino", "gambling", "bet365", "fuck", "hentai")

MAX_URL_LEN = 2000


class Kind(Enum):
    NORMAL = "normal"
    IP_LITERAL = "ip_literal"
    I2P = "i2p"
    YGGDRASIL = "yggdrasil"
    WS = "ws"


@dataclass
class Entry:
    url: str
    scheme: str
    host: str
    port: int | None
    kind: Kind
    sources: set[str] = field(default_factory=set)


@dataclass
class Blacklist:
    hosts: set[str]
    suffixes: set[str]
    ips: set[ipaddress._BaseNetwork]
    keywords: set[str]


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize(raw: str) -> str | None:
    if not raw or len(raw) > MAX_URL_LEN:
        return None
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in raw):
        return None
    try:
        parts = urllib.parse.urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in SCHEME_RANK:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if not host:
        return None
    host_out = f"[{host}]" if ":" in host else host
    netloc = f"{host_out}:{port}" if port is not None else host_out
    path = parts.path
    if path == "/":
        path = ""
    url = f"{scheme}://{netloc}{path}"
    if parts.query:
        url += "?" + parts.query
    return url


def _classify(scheme: str, host: str, source: str) -> Kind:
    if source == "i2p":
        return Kind.I2P
    if source in ("yggdrasil", "yggdrasil_ip"):
        return Kind.YGGDRASIL
    if scheme in ("ws", "wss"):
        return Kind.WS
    if _is_ip_literal(host):
        return Kind.IP_LITERAL
    return Kind.NORMAL


def parse_entry(raw: str, source: str) -> Entry | None:
    url = normalize(raw)
    if url is None:
        return None
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    return Entry(
        url=url,
        scheme=parts.scheme,
        host=host,
        port=parts.port,
        kind=_classify(parts.scheme, host, source),
        sources={source},
    )


def load_blacklist(path: Path) -> Blacklist:
    bl = Blacklist(hosts=set(), suffixes=set(), ips=set(), keywords=set())
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("keyword:"):
            kw = line[len("keyword:"):].strip().lower()
            if kw:
                bl.keywords.add(kw)
        elif line.startswith("*."):
            bl.suffixes.add(line[2:].lower())
        else:
            try:
                bl.ips.add(ipaddress.ip_network(line, strict=False))
            except ValueError:
                bl.hosts.add(line.lower())
    return bl


def is_blocked(entry: Entry, resolved: list[str], bl: Blacklist) -> bool:
    host = entry.host.lower()
    if host in bl.hosts:
        return True
    if any(host == s or host.endswith("." + s) for s in bl.suffixes):
        return True
    if any(k in host for k in bl.keywords):
        return True
    if any(k in host for k in VULGAR_KEYWORDS):
        return True
    candidates = list(resolved)
    if _is_ip_literal(host) and host not in candidates:
        candidates.append(host)
    ips = []
    for item in candidates:
        try:
            ips.append(ipaddress.ip_address(item))
        except ValueError:
            continue
    if any(ip_obj in net for ip_obj in ips for net in bl.ips):
        return True
    if entry.kind not in (Kind.YGGDRASIL, Kind.I2P):
        for a in ips:
            if (
                a.is_private
                or a.is_loopback
                or a.is_link_local
                or a.is_reserved
                or a.is_multicast
                or a.is_unspecified
            ):
                return True
    return False


def dedupe(entries: list[Entry], resolve: Callable[[str], list[str]]) -> list[Entry]:
    groups: dict[str, list[Entry]] = {}
    order: list[str] = []
    for e in entries:
        if _is_ip_literal(e.host):
            ips = [e.host]
        else:
            try:
                ips = list(resolve(e.host) or [])
            except Exception:
                ips = []
        key = f"ip:{sorted(ips)[0]}" if ips else f"host:{e.host}"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(e)
    out = []
    for key in order:
        members = groups[key]
        keep = min(
            members,
            key=lambda e: (SCHEME_RANK.get(e.scheme, 99), 1 if e.kind == Kind.IP_LITERAL else 0, e.url),
        )
        merged: set[str] = set()
        for m in members:
            merged |= m.sources
        out.append(replace(keep, sources=merged))
    return out


# ---------------------------------------------------------------------------
# Stage 2: announce probes (BEP-3 / BEP-15) and scoring
# ---------------------------------------------------------------------------

DEFAULT_PORTS = {"udp": 6969, "http": 80, "https": 443}


@dataclass
class ProbeResult:
    url: str
    ok: bool
    rtt_ms: float | None
    success_rate: float
    attempts: int
    detail: str
    rtt_std_ms: float | None = None


def _udp_announce(host: str, port: int, timeout: float) -> tuple[float, str]:
    """One BEP-15 connect + announce round trip. Returns (rtt_ms, detail)."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    conn = socket.socket(family, socket.SOCK_DGRAM)
    conn.settimeout(timeout)
    try:
        conn.connect((host, port))
        txn = int.from_bytes(os.urandom(4), "big")
        t0 = time.perf_counter()
        conn.send(struct.pack("!QII", 0x41727101980, 0, txn))
        data = conn.recv(64)
        action, txn_back, conn_id = struct.unpack("!IIQ", data[:16])
        if action != 0 or txn_back != txn:
            raise ValueError("bad connect response")
        connect_rtt = (time.perf_counter() - t0) * 1000

        info_hash = hashlib.sha1(os.urandom(20)).digest()
        peer_id = b"-PM0001-" + os.urandom(12)
        ann_txn = int.from_bytes(os.urandom(4), "big")
        ann_req = struct.pack(
            "!QII20s20sQQQIIIIH",
            conn_id, 1, ann_txn, info_hash, peer_id,
            0, 0, 0,  # downloaded, left, uploaded
            0, 0, 0, 0,  # event, ip, key, numwant
            6881,  # port
        )
        t1 = time.perf_counter()
        conn.send(ann_req)
        adata = conn.recv(2048)
        a_action, a_txn = struct.unpack("!II", adata[:8])
        if a_action == 3:
            raise ValueError("announce error: " + adata[8:108].decode(errors="replace"))
        if a_action != 1 or a_txn != ann_txn:
            raise ValueError("bad announce response")
        return (time.perf_counter() - t1) * 1000, "announce"
    except (socket.timeout, TimeoutError):
        raise TimeoutError("udp timeout")
    except OSError:
        raise
    finally:
        conn.close()


def _udp_announce_with_connect_fallback(host: str, port: int, timeout: float) -> tuple[float, str]:
    """Full announce, falling back to connect-handshake RTT when announce hangs."""
    try:
        return _udp_announce(host, port, timeout)
    except TimeoutError:
        # Retry handshake-only: if connect works but announce hangs, use connect RTT.
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        conn = socket.socket(family, socket.SOCK_DGRAM)
        conn.settimeout(timeout)
        try:
            conn.connect((host, port))
            txn = int.from_bytes(os.urandom(4), "big")
            t0 = time.perf_counter()
            conn.send(struct.pack("!QII", 0x41727101980, 0, txn))
            data = conn.recv(64)
            action, txn_back, _ = struct.unpack("!IIQ", data[:16])
            if action == 0 and txn_back == txn:
                return (time.perf_counter() - t0) * 1000, "connect-only"
            raise ValueError("bad connect response")
        finally:
            conn.close()


async def probe_udp(url: str, timeout: float = 10.0) -> ProbeResult:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or DEFAULT_PORTS["udp"]
    try:
        rtt, detail = await asyncio.to_thread(_udp_announce_with_connect_fallback, host, port, timeout)
        return ProbeResult(url=url, ok=True, rtt_ms=rtt, success_rate=1.0, attempts=1, detail=detail)
    except Exception as exc:
        return ProbeResult(
            url=url, ok=False, rtt_ms=None, success_rate=0.0, attempts=1,
            detail=f"udp-fail: {exc}"[:200],
        )


def _http_announce(url: str, timeout: float) -> float:
    """One BEP-3 GET announce. Returns rtt_ms; raises on failure."""
    info_hash = hashlib.sha1(os.urandom(20)).digest()
    peer_id = b"-PM0001-" + os.urandom(12)
    query = "&".join([
        "info_hash=" + urllib.parse.quote(info_hash),
        "peer_id=" + urllib.parse.quote(peer_id),
        "port=6881", "uploaded=0", "downloaded=0", "left=0",
        "compact=1", "numwant=0",
    ])
    sep = "&" if "?" in url else "?"
    full = url + sep + query
    req = urllib.request.Request(full, headers={"User-Agent": "Pmwiu-Tracker-List/1.0"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    t0 = time.perf_counter()
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read(4096)
    rtt = (time.perf_counter() - t0) * 1000
    if not body.startswith(b"d") or b"14:failure reason" in body:
        raise ValueError("tracker refused announce")
    if not (b"8:interval" in body or b"5:peers" in body or b"6:peers6" in body):
        raise ValueError("unrecognized bencode response")
    return rtt


async def probe_http(url: str, timeout: float = 10.0) -> ProbeResult:
    try:
        rtt = await asyncio.to_thread(_http_announce, url, timeout)
        return ProbeResult(url=url, ok=True, rtt_ms=rtt, success_rate=1.0, attempts=1, detail="announce")
    except Exception as exc:
        return ProbeResult(
            url=url, ok=False, rtt_ms=None, success_rate=0.0, attempts=1,
            detail=f"http-fail: {exc}"[:200],
        )


async def probe_all(urls: list[str], rounds: int = 3, concurrency: int = 32) -> dict[str, ProbeResult]:
    sem = asyncio.Semaphore(concurrency)

    async def one_round(url: str) -> ProbeResult | None:
        async with sem:
            if url.startswith(("ws:", "wss:")):
                return None
            fn = probe_udp if url.startswith("udp:") else probe_http
            return await fn(url)

    tasks = {url: [asyncio.create_task(one_round(url)) for _ in range(rounds)] for url in urls}
    out: dict[str, ProbeResult] = {}
    for url, rounds_tasks in tasks.items():
        results = [r for r in await asyncio.gather(*rounds_tasks) if r is not None]
        successes = [r for r in results if r.ok]
        rtts = [r.rtt_ms for r in successes if r.rtt_ms is not None]
        rtt_ms = statistics.median(rtts) if rtts else None
        rtt_std = statistics.pstdev(rtts) if len(rtts) >= 2 else (0.0 if rtts else None)
        out[url] = ProbeResult(
            url=url,
            ok=bool(successes),
            rtt_ms=rtt_ms,
            success_rate=len(successes) / len(results) if results else 0.0,
            attempts=len(results),
            detail=f"{len(successes)}/{len(results)} ok",
            rtt_std_ms=rtt_std,
        )
    return out


def score(result: ProbeResult, history: dict | None, popularity: int, kind: Kind) -> float:
    hist = (history or {}).get(result.url)
    if not result.ok:
        return hist["score"] * 0.9 if hist else 0.0
    latency_score = 0.0 if result.rtt_ms is None else 1.0 / (1.0 + result.rtt_ms / 1000.0)
    stability = 1.0 if result.rtt_std_ms is None else 1.0 / (1.0 + result.rtt_std_ms / 100.0)
    pop_score = min(popularity / 2.0, 1.0)
    hist_bonus = 0.5 if hist and hist.get("in_best") else 0.0
    value = (
        0.45 * latency_score
        + 0.30 * result.success_rate
        + 0.10 * stability
        + 0.10 * pop_score
        + 0.05 * hist_bonus
    )
    if kind == Kind.IP_LITERAL:
        value *= 0.95
    return value


def apply_udp_history(
    results: dict[str, ProbeResult], history: dict | None
) -> tuple[dict[str, ProbeResult], bool]:
    """When every UDP probe failed (likely blocked egress), carry over metrics."""
    udp_urls = [u for u in results if u.startswith("udp:")]
    if not udp_urls:
        return results, False
    udp_blocked = all(results[u].success_rate == 0 for u in udp_urls)
    if not udp_blocked or not history:
        return results, udp_blocked
    out = dict(results)
    for u in udp_urls:
        hist = history.get(u)
        if out[u].success_rate == 0 and hist and hist.get("rtt_ms") is not None:
            new_sr = hist.get("success_rate", 0.0) * 0.9
            if new_sr > 0:
                out[u] = ProbeResult(
                    url=u, ok=True, rtt_ms=hist["rtt_ms"], success_rate=new_sr,
                    attempts=out[u].attempts, detail="udp-blocked: carried from history",
                )
    return out, True


# ---------------------------------------------------------------------------
# Stage 3: output writers, README auto-sections, main() orchestrator
# ---------------------------------------------------------------------------

FLOOR_ALIVE = 30
BEST_N = 49
MARK_META = ("<!-- META:START -->", "<!-- META:END -->")
MARK_LEADERBOARD = ("<!-- LEADERBOARD:START -->", "<!-- LEADERBOARD:END -->")


def select_best(scores: dict[str, float], n: int = 49) -> list[str]:
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    return [url for url, _ in ranked[:n]]


def write_list(path: Path, urls: list[str]) -> None:
    path.write_text("".join(u + "\n" for u in urls), encoding="utf-8")


def write_aria2(path: Path, urls: list[str]) -> None:
    path.write_text(",".join(urls) + ("\n" if urls else ""), encoding="utf-8")


def write_stats(path: Path, stats: dict) -> None:
    path.write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def needs_commit(before: dict[str, str], after: dict[str, str]) -> bool:
    return before != after


def resolve_host(host: str) -> list[str]:
    ips: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips


def fetch_source(url: str, timeout: float = 30.0) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Pmwiu-Tracker-List/1.0"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            return resp.read(2_000_000).decode("utf-8", errors="replace")
    except Exception:
        return None


def load_history(root: Path) -> dict:
    path = root / "stats.json"
    if not path.exists():
        return {}
    try:
        stats = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {t["url"]: t for t in stats.get("trackers", [])}


def _replace_marked(text: str, start: str, end: str, inner: str) -> str:
    i = text.index(start) + len(start)
    j = text.index(end)
    return text[:i] + "\n" + inner.strip("\n") + "\n" + text[j:]


def update_readme(text: str, rows: list[dict], meta: dict) -> str:
    date = str(meta.get("updated", "")).replace("-", "--")
    selected = meta.get("selected", 0)
    meta_inner = (
        f"![Last Update](https://img.shields.io/badge/更新-{date}-blue) "
        f"![Trackers](https://img.shields.io/badge/Top_49-{selected}-brightgreen)"
    )
    lines = ["| 序号 | Tracker | 协议 | 中位延迟 (ms) | 成功率 | 综合分 |", "| ---: | --- | --- | ---: | ---: | ---: |"]
    for row in rows:
        median = "—" if row.get("median_ms") is None else f"{row['median_ms']:.1f}"
        rate = f"{row.get('success_rate', 0.0) * 100:.0f}%"
        lines.append(
            f"| {row['rank']} | {row['url']} | {row['scheme'].upper()} | {median} | {rate} | {row['score']:.3f} |"
        )
    if not rows:
        lines.append("| — | 暂无数据 | — | — | — | — |")
    text = _replace_marked(text, *MARK_META, meta_inner)
    text = _replace_marked(text, *MARK_LEADERBOARD, "\n".join(lines))
    return text


def _parse_args(argv: list[str] | None) -> tuple[str, str | None]:
    argv = list(sys.argv[1:] if argv is None else argv)
    root = "."
    source_dir = None
    i = 0
    while i < len(argv):
        if argv[i] == "--root" and i + 1 < len(argv):
            root = argv[i + 1]
            i += 2
        elif argv[i] == "--source-dir" and i + 1 < len(argv):
            source_dir = argv[i + 1]
            i += 2
        else:
            i += 1
    return root, source_dir


def _pool_urls(pool: list[Entry]) -> list[str]:
    return [e.url for e in sorted(pool, key=lambda e: (-len(e.sources), e.url))]


def main(argv: list[str] | None = None) -> int:
    root_s, source_dir = _parse_args(argv)
    root = Path(root_s)
    bl_path = root / "blacklist.txt"
    bl = load_blacklist(bl_path) if bl_path.exists() else Blacklist(set(), set(), set(), set())

    raw_texts: dict[str, str | None] = {}
    for key, url in SOURCES.items():
        if source_dir is not None:
            p = Path(source_dir) / f"{key}.txt"
            raw_texts[key] = p.read_text(encoding="utf-8") if p.exists() else None
        else:
            raw_texts[key] = fetch_source(url)
    if all(v is None for v in raw_texts.values()):
        print("error: all sources failed")
        return 1

    entries: list[Entry] = []
    sources_meta: dict[str, dict] = {}
    for key, text in raw_texts.items():
        if text is None:
            sources_meta[key] = {"ok": False, "count": 0}
            continue
        count = 0
        for line in text.splitlines():
            e = parse_entry(line.strip(), key)
            if e is not None:
                entries.append(e)
                count += 1
        sources_meta[key] = {"ok": True, "count": count}

    resolved_cache: dict[str, list[str]] = {}

    def resolve_cached(host: str) -> list[str]:
        if host not in resolved_cache:
            try:
                resolved_cache[host] = resolve_host(host)
            except Exception:
                resolved_cache[host] = []
        return resolved_cache[host]

    kept: list[Entry] = []
    for e in entries:
        resolved = [e.host] if _is_ip_literal(e.host) else resolve_cached(e.host)
        if not is_blocked(e, resolved, bl):
            kept.append(e)

    uniq = dedupe(kept, resolve=resolve_cached)

    testable = [
        e for e in uniq
        if e.kind in (Kind.NORMAL, Kind.IP_LITERAL) and e.scheme in ("udp", "http", "https")
    ]
    ws_pool = [e for e in uniq if e.kind == Kind.WS]
    i2p_pool = [e for e in uniq if e.kind == Kind.I2P]
    ygg_pool = [e for e in uniq if e.kind == Kind.YGGDRASIL]

    history = load_history(root)
    results = asyncio.run(probe_all([e.url for e in testable]))
    results, udp_blocked = apply_udp_history(results, history)

    entry_by_url = {e.url: e for e in testable}
    scores = {
        u: score(results[u], history, len(entry_by_url[u].sources), entry_by_url[u].kind)
        for u in results
    }
    alive_scores = {u: s for u, s in scores.items() if results[u].success_rate > 0}
    alive_sorted = select_best(alive_scores, len(alive_scores))
    if len(alive_sorted) < FLOOR_ALIVE:
        print(
            f"abort: alive trackers {len(alive_sorted)} < floor {FLOOR_ALIVE}; keeping previous lists"
        )
        return 2

    best = select_best(alive_scores, BEST_N)
    best_set = set(best)

    write_list(root / "trackers_best.txt", best)
    write_list(root / "trackers_all.txt", alive_sorted + _pool_urls(ws_pool))
    write_list(root / "trackers_udp.txt", [u for u in alive_sorted if u.startswith("udp:")])
    write_list(root / "trackers_http.txt", [u for u in alive_sorted if u.startswith("http:")])
    write_list(root / "trackers_https.txt", [u for u in alive_sorted if u.startswith("https:")])
    write_list(
        root / "trackers_ip.txt",
        [u for u in alive_sorted if entry_by_url[u].kind == Kind.IP_LITERAL],
    )
    write_list(root / "trackers_i2p.txt", _pool_urls(i2p_pool))
    write_list(root / "trackers_yggdrasil.txt", _pool_urls(ygg_pool))
    write_aria2(root / "trackers_aria2.txt", best)

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    trackers_rows = []
    for rank, u in enumerate(select_best(scores, len(scores)), 1):
        r = results[u]
        e = entry_by_url[u]
        trackers_rows.append(
            {
                "url": u,
                "scheme": e.scheme,
                "kind": e.kind.value,
                "median_ms": r.rtt_ms,
                "success_rate": r.success_rate,
                "score": scores[u],
                "rank": rank,
                "in_best": u in best_set,
            }
        )
    stats = {
        "generated_at": generated_at,
        "sources": sources_meta,
        "counts": {"alive": len(alive_sorted), "selected": len(best)},
        "udp_probes_blocked": udp_blocked,
        "trackers": trackers_rows,
    }
    write_stats(root / "stats.json", stats)

    readme_path = root / "README.md"
    if readme_path.exists():
        rows = [
            {
                "rank": rank,
                "url": u,
                "scheme": entry_by_url[u].scheme,
                "median_ms": results[u].rtt_ms,
                "success_rate": results[u].success_rate,
                "score": scores[u],
            }
            for rank, u in enumerate(best, 1)
        ]
        meta = {"updated": generated_at[:10], "selected": len(best)}
        readme_path.write_text(
            update_readme(readme_path.read_text(encoding="utf-8"), rows, meta),
            encoding="utf-8",
        )

    print(
        f"done: sources={ {k: v['count'] for k, v in sources_meta.items()} } "
        f"alive={len(alive_sorted)} selected={len(best)} udp_blocked={udp_blocked}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
