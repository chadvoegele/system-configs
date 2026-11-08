import json
import unittest
from pathlib import Path
import sys
from collections import deque
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "chadrouter.lan/usr/local/sbin"))
import wan_failover as wan


class PolicyTests(unittest.TestCase):
    def test_dependencies_present(self):
        with patch.object(wan.shutil, "which", return_value="/usr/bin/tool"), \
             patch.object(wan.ssl, "create_default_context") as context:
            context.return_value.get_ca_certs.return_value = [{"subject": "CA"}]
            wan.check_dependencies()

    def test_missing_commands_report_packages(self):
        with patch.object(wan.shutil, "which", return_value=None), \
             patch.object(wan.ssl, "create_default_context") as context:
            context.return_value.get_ca_certs.return_value = [{}]
            with self.assertRaises(RuntimeError) as failure:
                wan.check_dependencies()
            for package in ("iproute2", "nftables", "conntrack-tools",
                            "wireguard-tools", "iputils"):
                self.assertIn(package, str(failure.exception))

    def test_empty_ca_store_fails(self):
        with patch.object(wan.shutil, "which", return_value="/usr/bin/tool"), \
             patch.object(wan.ssl, "create_default_context") as context:
            context.return_value.get_ca_certs.return_value = []
            with self.assertRaisesRegex(RuntimeError, "ca-certificates"):
                wan.check_dependencies()

    def test_broken_ca_store_fails(self):
        with patch.object(wan.shutil, "which", return_value="/usr/bin/tool"), \
             patch.object(wan.ssl, "create_default_context", side_effect=OSError("bad store")):
            with self.assertRaisesRegex(RuntimeError, "repair system trust store"):
                wan.check_dependencies()

    def test_health_mapping(self):
        for health, desired in [(set(), "outage"), ({"fiber"}, "fiber"),
                                ({"cable"}, "cable"), (set(wan.WANS), "split")]:
            self.assertEqual(wan.policy_for(frozenset(health)), desired)

    def test_five_consistent_observations(self):
        history = deque(maxlen=5)
        with patch.object(wan, "check_health", return_value=frozenset({"cable"})), \
             patch.object(wan, "get_policy", return_value="split"), \
             patch.object(wan, "apply_policy") as apply, \
             patch.object(wan, "ensure_vpn"):
            for _ in range(4):
                wan.reconcile(history, False)
            apply.assert_not_called()
            wan.reconcile(history, False)
            apply.assert_called_once_with("cable")

    def test_isolated_failure(self):
        history = deque(["split", "split", "cable", "split"], maxlen=5)
        with patch.object(wan, "check_health", return_value=frozenset(wan.WANS)), \
             patch.object(wan, "get_policy", return_value="split"), \
             patch.object(wan, "apply_policy") as apply:
            wan.reconcile(history, False)
            apply.assert_not_called()

    def test_dry_run(self):
        history = deque(["fiber"] * 4, maxlen=5)
        with patch.object(wan, "check_health", return_value=frozenset({"fiber"})), \
             patch.object(wan, "get_policy", return_value="split"), \
             patch.object(wan, "apply_policy") as apply, \
             patch.object(wan, "ensure_vpn") as vpn:
            wan.reconcile(history, True)
            apply.assert_not_called()
            vpn.assert_called_once_with(True)

    def test_outage_preserves_policy(self):
        history = deque(["outage"] * 4, maxlen=5)
        with patch.object(wan, "check_health", return_value=frozenset()), \
             patch.object(wan, "get_policy", return_value="fiber"), \
             patch.object(wan, "apply_policy") as apply, \
             patch.object(wan, "ensure_vpn") as vpn:
            wan.reconcile(history, False)
            apply.assert_not_called()
            vpn.assert_not_called()

    def test_vpn_checked_without_policy_change(self):
        history = deque(["split"] * 4, maxlen=5)
        with patch.object(wan, "check_health", return_value=frozenset(wan.WANS)), \
             patch.object(wan, "get_policy", return_value="split"), \
             patch.object(wan, "apply_policy") as apply, \
             patch.object(wan, "ensure_vpn") as vpn:
            wan.reconcile(history, False)
            apply.assert_not_called()
            vpn.assert_called_once_with(False)

    def test_vpn_dry_run_never_changes_host(self):
        with patch.object(wan, "probe_vpn", return_value=False), \
             patch.object(wan, "run") as run, \
             patch.object(wan, "delete_connections") as delete:
            wan.ensure_vpn(True)
            run.assert_not_called()
            delete.assert_not_called()

    def test_policy_inspection(self):
        for mode, overrides, expected in [
                ("split", [], "split"),
                ("fiber", [{"table": "fiber"}], "fiber"),
                ("cable", [{"table": 200}], "cable"),
                ("split", [{"table": "fiber"}], "inconsistent")]:
            with patch.object(wan, "get_assignment_rules", return_value=[({}, mode)]), \
                 patch.object(wan, "get_override_rules", return_value=overrides):
                self.assertEqual(wan.get_policy(), expected)

    def test_build_firewall_commands(self):
        rules = [({"family": "inet", "table": "filter", "chain": chain,
                   "handle": handle}, "split")
                 for chain, handle in [("prerouting_policy", 1), ("output_policy", 2)]]
        split = wan.build_assignment_commands(rules, "split")
        cable = wan.build_assignment_commands(rules, "cable")
        self.assertEqual(split.count("numgen random mod 2"), 2)
        self.assertEqual(cable.count("ct mark set 2"), 2)
        self.assertEqual(cable.count("iifname"), 1)

    def test_override_refuses_unknown_table(self):
        with patch.object(wan, "run", return_value=json.dumps(
                [{"priority": 90, "table": "unexpected"}])):
            with self.assertRaises(RuntimeError):
                wan.get_override_rules()

    def test_urllib_probe_validates_status_and_url(self):
        url = wan.PROBES[0]
        with patch.object(wan.urllib.request, "build_opener") as build:
            response = build.return_value.open.return_value.__enter__.return_value
            response.status, response.url = 204, url
            self.assertTrue(wan.probe_endpoint("fiber", url))
            build.return_value.open.assert_called_with(url, timeout=wan.TIMEOUT)
            response.status = 200
            self.assertFalse(wan.probe_endpoint("fiber", url))
            response.status, response.url = 204, "https://other.example/"
            self.assertFalse(wan.probe_endpoint("fiber", url))

    def test_https_connection_uses_bound_socket_and_tls_hostname(self):
        with patch.object(wan, "open_wan_socket") as open_socket, \
             patch.object(wan.ssl, "create_default_context") as context:
            connection = wan.WanHTTPSConnection(
                "example.com", wan="fiber", context=context.return_value)
            connection.connect()
            open_socket.assert_called_once_with("fiber", wan.socket.SOCK_STREAM)
            open_socket.return_value.connect.assert_called_once_with(("example.com", 443))
            context.return_value.wrap_socket.assert_called_once_with(
                open_socket.return_value, server_hostname="example.com")

    def test_failed_connection_closes_socket(self):
        with patch.object(wan, "open_wan_socket") as open_socket:
            open_socket.return_value.connect.side_effect = OSError("WAN down")
            connection = wan.WanHTTPSConnection("example.com", wan="cable")
            with self.assertRaises(OSError):
                connection.connect()
            open_socket.return_value.close.assert_called_once()

    def test_health_checks_both_wans(self):
        with patch.object(wan, "check_wan", side_effect=[True, False]) as check:
            self.assertEqual(wan.check_health(), frozenset({"fiber"}))
            self.assertEqual(check.call_count, 2)

    def test_probe_socket_is_pinned(self):
        with patch.object(wan.socket, "socket") as factory:
            wan.open_wan_socket("fiber", wan.socket.SOCK_STREAM)
            factory.return_value.setsockopt.assert_any_call(
                wan.socket.SOL_SOCKET, wan.socket.SO_BINDTODEVICE, b"enp1s0f0\0")


if __name__ == "__main__":
    unittest.main()
