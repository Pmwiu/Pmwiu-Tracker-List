"""Pmwiu Tracker List — tracker aggregation pipeline (stdlib only).

Stage 1 (pure logic): normalize / classify / blacklist / dedupe.
Probing and orchestration are added in later stages.
"""

import ipaddress
import urllib.parse
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
