# Private nginx VIP proposal

Chad's Agent — coordinated with Dockerops MR !95. **Not applied live.**

Add `10.0.0.95/32` to the existing primary NIC alongside DHCP `.99` and Git SSH
alias `.96`. The checked-in DHCP dynamic pool starts at `.100`; `.95` is not a
fixed reservation or existing checked-in allocation. `.97` belongs to chaddisk.
An administrator must still check for unmanaged/static conflicts before applying.
No interface, DHCP lease, host SSH bind or Git SSH address is replaced.

The router resolves `chadserver.lan.voegele.me` and service subdomains to `.95`;
`lan0-sarah.chadserver.lan.voegele.me` is an explicit alias as well. The internal
zone does not forward unresolved/AAAA queries to public DNS. Existing
`chadserver.lan` SSH resolution remains `.99`.

This is **LAN and VPN accessible, not Internet accessible**, per Chad's clarified
request. Public forwarding remains fixed at `.99` for web and `.96` for Git SSH.
No VPS/router DNAT/SNAT or firewall accept scope is widened. VPN clients already
route `10.0.0.0/16`; the checked-in phone config uses router DNS `10.0.0.1`.
HTTPS to `.95` does not match the VPS `.99` web-SNAT rule, so VPN client source
addresses are preserved. No new public IP/port forwarding is added.

Dockerops binds the new internal nginx vhosts specifically to `.95:443`, not a
VPN interface/address and not the public address. Public-address Host/SNI
spoofing must not reach this vhost. Defence in depth denies the public-forwarding
source `.254`, permits LAN/VPN ranges and requires Sarah's existing Bearer key.
DNS alone is not treated as an access-control boundary.

## Apply / validate / rollback

Review both changes first. Apply the network/DNS entries using the normal
privileged deployment process; validate syntax and address availability before
reconfiguring the primary NIC over SSH. No live IP/DNS/firewall modification was
made while preparing this PR.

1. Verify `.95` is unallocated and preserve a network/SSH rollback path.
2. Apply the additive network address and router DNS changes. Confirm `.99`
   host SSH, `.96` Git SSH and DHCP service still work.
3. Issue the public DNS-01 base/wildcard certificate through existing Lego /
   Route53 configuration in Dockerops, then load the internal nginx listener.
4. Test DNS from LAN and VPN, trusted TLS/Bearer voice requests to the new host,
   and rejection via the public address even with forged Host/SNI. No private CA
   or nonstandard HTTPS port is required.
5. Coordinate the documented Sarah shared-state/cutover procedure separately;
   do not blindly mount empty config volumes over the existing agent state.

For rollback, remove/reload nginx's internal listener **before** removing its
address. Remove only the new zone/alias/address; keep `.96`, `.99`, DHCP, public
forwarding and existing state untouched.

Offline checks: `python -m unittest discover -s tests -p test_internal_nginx.py`
checks allocation, preserved aliases, DNS entries and unchanged public NAT
rules. This is not a live deployment/reachability or unmanaged-address proof.
