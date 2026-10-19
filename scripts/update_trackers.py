"""Pmwiu Tracker List — tracker aggregation pipeline (stdlib only).

Stage 1 (pure logic): normalize / classify / blacklist / dedupe.
Stage 2 (network): BEP-3 / BEP-15 announce probes and multi-dim scoring.
"""

import asyncio
import hashlib
import ipaddress
import os
import socket
import statistics
import struct
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
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
