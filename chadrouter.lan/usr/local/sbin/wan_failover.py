#!/usr/bin/env python
"""chadrouter.lan WAN health reconciler; run locally on the router as root.

Flow: WAN-pinned HTTPS probes -> health -> five observations -> host policy
      -> routing/firewall update -> targeted conntrack cleanup -> VPN check

Requirements: Python 3, iproute2, nftables, conntrack-tools, wireguard-tools, ping.
Review before deployment. Runtime changes are not persisted to networkd/nftables.
Dry run makes no routing, firewall, conntrack, or WireGuard changes.
"""

import argparse
from collections import deque
from dataclasses import dataclass
import fcntl
import http.client
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

logger = logging.getLogger("wan_failover")


@dataclass(frozen=True)
class Wan:
    name: str
    interface: str
    mark: int
    table_id: int


WANS = (Wan(name="fiber", interface="enp1s0f0", mark=1, table_id=100),
        Wan(name="cable", interface="eno1", mark=2, table_id=200))
# Reserved for this script; priority 50 still preserves LAN and tunnel routes.
POLICY_PRIORITY = 90
TIMEOUT = 2


def run(*args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True,
                            timeout=10, check=True)
    return result.stdout


def open_wan_socket(wan, kind):
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.settimeout(TIMEOUT)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                        wan.interface.encode() + b"\0")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, wan.mark)
        return sock
    except Exception:
        sock.close()
        raise


class WanHTTPSConnection(http.client.HTTPSConnection):
    """Keep urllib's HTTP/TLS handling while selecting the outgoing interface."""

    def __init__(self, host, *, wan, **kwargs):
        super().__init__(host, **kwargs)
        self.wan = wan

    def connect(self):
        raw = open_wan_socket(self.wan, socket.SOCK_STREAM)
        try:
            raw.connect((self.host, self.port))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


class WanHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, wan):
        super().__init__(context=ssl.create_default_context())
        self.wan = wan

    def https_open(self, request):
        def connect(host, **kwargs):
            return WanHTTPSConnection(host, wan=self.wan, **kwargs)

        return self.do_open(connect, request, context=self._context)


def probe_endpoint(wan, url):
    # Bypass environment proxies; otherwise the proxy could mask a failed WAN.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), WanHTTPSHandler(wan))
    with opener.open(url, timeout=TIMEOUT) as response:
        return response.status == 204 and response.url == url


def check_wan(wan):
    probes = ("https://cp.cloudflare.com/generate_204",
              "https://connectivitycheck.gstatic.com/generate_204")
    for url in probes:
        try:
            if probe_endpoint(wan, url):
                return True
            logger.warning("probe wan=%s target=%s unexpected response",
                           wan.name, url)
        except (OSError, ValueError, urllib.error.URLError) as error:
            logger.warning("probe wan=%s target=%s failed: %s",
                           wan.name, url, error)
    return False


def check_health():
    return frozenset(wan.name for wan in WANS if check_wan(wan))


def get_policy_rules():
    ruleset = json.loads(run("nft", "-j", "list", "ruleset"))
    rules = []
    for item in ruleset["nftables"]:
        rule = item.get("rule", {})
        if rule.get("chain") in ("prerouting_policy", "output_policy"):
            for expression in rule["expr"]:
                value = expression.get("mangle", {})
                if value.get("key") == {"ct": {"key": "mark"}}:
                    assignment = value["value"]
                    if isinstance(assignment, dict) and "map" in assignment:
                        rules.append((rule, "split"))
                    if isinstance(assignment, int) and any(
                            "ct" in str(e.get("match", {}).get("left", {}))
                            and e.get("match", {}).get("right") == "new"
                            for e in rule["expr"]):
                        rules.append((rule, next(wan.name for wan in WANS
                                                 if wan.mark == assignment)))
    if len(rules) != 2 or len({r[0]["chain"] for r in rules}) != 2:
        raise RuntimeError("Expected two WAN policy rules; inspect nftables")
    if len({mode for _, mode in rules}) != 1:
        raise RuntimeError("WAN policy rules disagree; inspect nftables")
    return rules


def get_policy_routes():
    rules = json.loads(run("ip", "-j", "-4", "rule", "show"))
    routes = [r for r in rules if r.get("priority") == POLICY_PRIORITY]
    allowed_tables = {wan.name for wan in WANS} | {wan.table_id for wan in WANS}
    for route in routes:
        if route.get("table") not in allowed_tables:
            raise RuntimeError("Priority 90 is occupied; choose a free priority")
    return routes


def route_matches(route, wan):
    return (route["table"] in (wan.name, wan.table_id)
            and route.get("src", "all") == "all"
            and route.get("dst", "all") == "all"
            and route.keys() <= {"priority", "table", "src", "dst", "protocol"})


def policy_matches(desired):
    if desired not in {"split", "fiber", "cable"}:
        raise ValueError(f"Cannot match WAN policy: {desired}")
    rules = get_policy_rules()
    routes = get_policy_routes()
    logger.info("desired=%s current_assignments=%s current_routes=%s",
                desired, [policy for _, policy in rules], routes)
    if any(policy != desired for _, policy in rules):
        return False
    if desired == "split":
        return not routes
    wan = next(wan for wan in WANS if wan.name == desired)
    return len(routes) == 1 and route_matches(routes[0], wan)


def policy_for(health):
    return {frozenset(wan.name for wan in WANS): "split",
            frozenset({"fiber"}): "fiber", frozenset({"cable"}): "cable",
            frozenset(): "outage"}[health]


def build_policy_commands(rules, policy):
    value = ("numgen random mod 2 map { 0 : 1, 1 : 2 }"
             if policy == "split" else str(next(wan.mark for wan in WANS
                                               if wan.name == policy)))
    commands = []
    for rule, _ in rules:
        incoming = ('iifname { "enp1s0f1", "wg0" } '
                    if rule["chain"] == "prerouting_policy" else "")
        commands.append(
            f'replace rule {rule["family"]} {rule["table"]} {rule["chain"]} '
            f'handle {rule["handle"]} {incoming}ct state new ct mark 0 '
            f'ct mark set {value}')
    return "\n".join(commands) + "\n"


def delete_connections(*filters):
    result = subprocess.run(["conntrack", "-D", *filters], capture_output=True,
                            text=True, timeout=10)
    # conntrack returns 1 when no matching entries exist.
    if result.returncode not in (0, 1) or (
            result.returncode == 1 and "0 flow entries" not in result.stderr):
        raise RuntimeError(f"conntrack cleanup failed: {result.stderr.strip()}")
    logger.info("conntrack cleanup filters=%s result=%s",
                filters, result.stderr.strip())


def apply_policy(policy):
    wan = next((wan for wan in WANS if wan.name == policy), None)
    if policy != "split" and wan is None:
        raise ValueError(f"Cannot apply WAN policy: {policy}")
    rules = get_policy_rules()
    existing = get_policy_routes()
    commands = build_policy_commands(rules, policy)
    run("nft", "-c", "-f", "-", input=commands)
    routes_match = (wan is not None and len(existing) == 1
                    and route_matches(existing[0], wan))
    if not routes_match:
        if wan is not None:
            # Install the working route before removing earlier policy routes.
            run("ip", "-4", "rule", "add", "priority", str(POLICY_PRIORITY),
                "table", policy)
        for rule in existing:
            run("ip", "-4", "rule", "del", "priority", str(POLICY_PRIORITY),
                "table", str(rule["table"]))
    run("nft", "-f", "-", input=commands)
    if wan is not None:
        failed = next(other for other in WANS if other.name != policy)
        delete_connections("--mark", str(failed.mark))
    logger.info("applied policy=%s", policy)


def is_vpn_healthy():
    result = subprocess.run(["ping", "-n", "-I", "wg0", "-c", "1", "-W", "2",
                             "192.168.0.254"], capture_output=True, timeout=4)
    return result.returncode == 0


def ensure_vpn(dry_run):
    if is_vpn_healthy():
        logger.debug("VPN healthy")
        return
    if dry_run:
        logger.warning("DRY RUN: would refresh VPN endpoint and clear peer UDP connection")
        return
    endpoints = run("wg", "show", "wg0", "endpoints").splitlines()
    if len(endpoints) != 1:
        raise RuntimeError("Expected one wg0 peer; inspect WireGuard configuration")
    peer, endpoint = endpoints[0].split()
    host, port = endpoint.rsplit(":", 1)
    vpn_endpoint = "vpn.voegele.me:51871"
    run("wg", "set", "wg0", "peer", peer, "endpoint", vpn_endpoint)
    delete_connections("-p", "udp", "--orig-dst", host, "--dport", port)
    if is_vpn_healthy():
        logger.info("VPN recovered")
    else:
        logger.warning("VPN recovery attempted; awaiting tunnel reachability")


def reconcile(history, dry_run):
    health = check_health()
    desired = policy_for(health)
    history.append(desired)
    stable = len(history) == history.maxlen and len(set(history)) == 1
    logger.info("health=%s desired=%s history=%s stable=%s",
                sorted(health), desired, list(history), stable)
    try:
        matches = desired != "outage" and policy_matches(desired)
        if stable and desired != "outage" and not matches:
            if dry_run:
                logger.info("DRY RUN: would apply policy=%s", desired)
            else:
                apply_policy(desired)
                if not policy_matches(desired):
                    raise RuntimeError(
                        f"Applied policy={desired} but settings still disagree; "
                        "inspect nftables and priority 90 IP rules")
    finally:
        if health:
            ensure_vpn(dry_run)


def check_dependencies():
    commands = {"ip": "iproute2", "nft": "nftables",
                "conntrack": "conntrack-tools", "wg": "wireguard-tools",
                "ping": "iputils"}
    missing = [f"{command} (install {package})"
               for command, package in commands.items()
               if shutil.which(command) is None]
    try:
        certificates = ssl.create_default_context().get_ca_certs()
        if len(certificates) == 0:
            missing.append("CA certificates (install/update ca-certificates)")
    except (OSError, ssl.SSLError) as error:
        missing.append(f"CA certificates (repair system trust store: {error})")
    if missing:
        raise RuntimeError("Missing dependencies: " + "; ".join(missing))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--log-file", default="/var/log/wan-failover.log")
    args = parser.parse_args()
    if args.interval <= 0 or args.samples < 1:
        parser.error("interval and samples must be positive")
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.StreamHandler(), RotatingFileHandler(
                            args.log_file, maxBytes=5_000_000, backupCount=3)])
    if os.geteuid() != 0:
        parser.error("run as root on chadrouter.lan, including in dry-run mode")
    if socket.gethostname().split(".")[0] != "chadrouter":
        parser.error("this script is configured specifically for chadrouter.lan")
    try:
        check_dependencies()
    except RuntimeError as error:
        logger.error("Startup failed: %s", error)
        parser.exit(1)
    with open("/run/wan-failover.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        history = deque(maxlen=args.samples)
        logger.info("started dry_run=%s interval=%s samples=%s", args.dry_run,
                    args.interval, args.samples)
        while True:
            started = time.monotonic()
            try:
                reconcile(history, args.dry_run)
            except Exception:
                history.clear()
                logger.exception("Check failed; inspect configuration and command errors")
            time.sleep(max(0, args.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
