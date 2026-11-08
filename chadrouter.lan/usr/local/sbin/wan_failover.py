#!/usr/bin/env python3
"""chadrouter.lan WAN health reconciler; run locally on the router as root.

Flow: WAN-pinned HTTPS probes -> health -> five observations -> host policy
      -> routing/firewall update -> targeted conntrack cleanup -> VPN check

Requirements: Python 3, iproute2, nftables, conntrack-tools, wireguard-tools, ping.
Review before deployment. Runtime changes are not persisted to networkd/nftables.
Dry run makes no routing, firewall, conntrack, or WireGuard changes.
"""

import argparse
from collections import deque
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

LOG = logging.getLogger("wan_failover")
WANS = {"fiber": ("enp1s0f0", 1), "cable": ("eno1", 2)}
VPN_ENDPOINT = "vpn.voegele.me:51871"
# Reserved for this script; priority 50 still preserves LAN and tunnel routes.
POLICY_PRIORITY = 90
PROBES = ("https://cp.cloudflare.com/generate_204",
          "https://connectivitycheck.gstatic.com/generate_204")
TIMEOUT = 2


def run(*args, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True,
                            timeout=10, check=True)
    return result.stdout


def open_wan_socket(wan, kind):
    interface, mark = WANS[wan]
    sock = socket.socket(socket.AF_INET, kind)
    sock.settimeout(TIMEOUT)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                    interface.encode() + b"\0")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    return sock


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
    for url in PROBES:
        try:
            if probe_endpoint(wan, url):
                return True
            LOG.warning("probe wan=%s target=%s unexpected response", wan, url)
        except (OSError, ValueError, urllib.error.URLError) as error:
            LOG.warning("probe wan=%s target=%s failed: %s", wan, url, error)
    return False


def check_health():
    return frozenset(wan for wan in WANS if check_wan(wan))


def get_assignment_rules():
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
                        rules.append((rule, {1: "fiber", 2: "cable"}[assignment]))
    if len(rules) != 2 or len({r[0]["chain"] for r in rules}) != 2:
        raise RuntimeError("Expected two WAN assignment rules; inspect nftables")
    if len({mode for _, mode in rules}) != 1:
        raise RuntimeError("WAN assignment rules disagree; inspect nftables")
    return rules


def get_override_rules():
    rules = json.loads(run("ip", "-j", "-4", "rule", "show"))
    overrides = [r for r in rules if r.get("priority") == POLICY_PRIORITY]
    for rule in overrides:
        if rule.get("table") not in ("fiber", "cable", 100, 200):
            raise RuntimeError("Priority 90 is occupied; choose a free priority")
    return overrides


def get_policy():
    mode = get_assignment_rules()[0][1]
    overrides = get_override_rules()
    expected = {"fiber": ("fiber", 100), "cable": ("cable", 200)}
    consistent = (mode == "split" and len(overrides) == 0) or (
        mode in expected and len(overrides) == 1
        and overrides[0]["table"] in expected[mode])
    return mode if consistent else "inconsistent"


def policy_for(health):
    return {frozenset(WANS): "split", frozenset({"fiber"}): "fiber",
            frozenset({"cable"}): "cable", frozenset(): "outage"}[health]


def build_assignment_commands(rules, desired):
    value = ("numgen random mod 2 map { 0 : 1, 1 : 2 }"
             if desired == "split" else str(WANS[desired][1]))
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
    LOG.info("conntrack cleanup filters=%s result=%s", filters, result.stderr.strip())


def apply_policy(desired):
    rules = get_assignment_rules()
    get_override_rules()
    commands = build_assignment_commands(rules, desired)
    run("nft", "-c", "-f", "-", input=commands)
    existing = get_override_rules()
    if desired in WANS and not any(
            r["table"] in (desired, {"fiber": 100, "cable": 200}[desired])
            for r in existing):
        # Install the working route before removing an earlier override.
        run("ip", "-4", "rule", "add", "priority", str(POLICY_PRIORITY),
            "table", desired)
    for rule in get_override_rules():
        table = str(rule["table"])
        if desired == "split" or table not in (desired, str({"fiber": 100, "cable": 200}[desired])):
            run("ip", "-4", "rule", "del", "priority", str(POLICY_PRIORITY), "table", table)
    run("nft", "-f", "-", input=commands)
    if desired in WANS:
        failed = next(wan for wan in WANS if wan != desired)
        delete_connections("--mark", str(WANS[failed][1]))
    LOG.info("applied policy=%s", desired)


def probe_vpn():
    result = subprocess.run(["ping", "-n", "-I", "wg0", "-c", "1", "-W", "2",
                             "192.168.0.254"], capture_output=True, timeout=4)
    return result.returncode == 0


def ensure_vpn(dry_run):
    if probe_vpn():
        LOG.debug("VPN healthy")
        return
    if dry_run:
        LOG.warning("DRY RUN: would refresh VPN endpoint and clear peer UDP connection")
        return
    endpoints = run("wg", "show", "wg0", "endpoints").splitlines()
    if len(endpoints) != 1:
        raise RuntimeError("Expected one wg0 peer; inspect WireGuard configuration")
    peer, endpoint = endpoints[0].split()
    host, port = endpoint.rsplit(":", 1)
    run("wg", "set", "wg0", "peer", peer, "endpoint", VPN_ENDPOINT)
    delete_connections("-p", "udp", "--orig-dst", host, "--dport", port)
    if probe_vpn():
        LOG.info("VPN recovered")
    else:
        LOG.warning("VPN recovery attempted; awaiting tunnel reachability")


def reconcile(history, dry_run, check_vpn=True):
    health = check_health()
    desired = policy_for(health)
    current = get_policy()
    history.append(desired)
    stable = len(history) == history.maxlen and len(set(history)) == 1
    LOG.info("health=%s desired=%s current=%s history=%s stable=%s",
             sorted(health), desired, current, list(history), stable)
    if stable and desired != "outage" and desired != current:
        if dry_run:
            LOG.info("DRY RUN: would apply policy=%s", desired)
        else:
            apply_policy(desired)
    if stable and desired != "outage" and (check_vpn or desired != current):
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
        LOG.error("Startup failed: %s", error)
        parser.exit(1)
    with open("/run/wan-failover.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        history = deque(maxlen=args.samples)
        LOG.info("started dry_run=%s interval=%s samples=%s", args.dry_run,
                 args.interval, args.samples)
        next_vpn_check = 0
        while True:
            started = time.monotonic()
            try:
                check_vpn = started >= next_vpn_check
                reconcile(history, args.dry_run, check_vpn)
                if check_vpn and len(history) == history.maxlen:
                    next_vpn_check = started + 30
            except Exception:
                history.clear()
                LOG.exception("Check failed; inspect configuration and command errors")
            time.sleep(max(0, args.interval - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
