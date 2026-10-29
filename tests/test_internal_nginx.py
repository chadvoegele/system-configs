"""Offline invariants for the proposed private nginx VIP; no network changes."""
from pathlib import Path
import ipaddress
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
VIP=ipaddress.ip_address('10.0.0.95')


class InternalVIPTests(unittest.TestCase):
    def test_existing_network_and_git_alias_retained(self):
        text=(ROOT/'chadserver.lan/etc/systemd/network/89-ethernet.network').read_text()
        addresses=re.findall(r'^Address=(.+)$',text,re.M)
        self.assertEqual(addresses.count('10.0.0.95/32'),1)
        self.assertIn('10.0.0.96/32',addresses)
        self.assertIn('DHCP=yes',text)
        self.assertEqual(ipaddress.ip_interface('10.0.0.95/32').ip,VIP)

    def test_outside_dynamic_pool_and_fixed_reservations(self):
        text=(ROOT/'chadrouter.lan/etc/dhcpd.conf').read_text()
        start,end=re.search(r'range\s+(\S+)\s+(\S+);',text).groups()
        self.assertFalse(ipaddress.ip_address(start)<=VIP<=ipaddress.ip_address(end))
        fixed=re.findall(r'fixed-address\s+(\S+);',text)
        self.assertNotIn(str(VIP),fixed)
        self.assertIn('10.0.0.97',fixed)  # chaddisk is not available.

    def test_internal_dns_base_and_service(self):
        hosts=(ROOT/'chadrouter.lan/etc/hosts').read_text()
        self.assertIn('10.0.0.95 chadserver.lan.voegele.me lan0-sarah.chadserver.lan.voegele.me',hosts)
        dns=(ROOT/'chadrouter.lan/etc/dnsmasq.conf').read_text()
        self.assertIn('address=/chadserver.lan.voegele.me/10.0.0.95',dns)
        self.assertIn('local=/chadserver.lan.voegele.me/',dns)

    def test_no_public_dnat_or_snat_target_added(self):
        text=(ROOT/'chadvm0.lan/etc/nftables.conf').read_text()
        self.assertIn('define chadserver_ip = 10.0.0.99',text)
        self.assertIn('define git_server_ip = 10.0.0.96',text)
        self.assertNotIn(str(VIP),text)
        self.assertIn('define vps_vpn_ip = 192.168.0.254',text)
        host=(ROOT/'chadserver.lan/etc/ssh/sshd_config.d/30-address.conf').read_text()
        self.assertIn('ListenAddress 10.0.0.99',host)


if __name__=='__main__':unittest.main()
