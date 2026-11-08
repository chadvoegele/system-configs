# Router WAN failover

`wan-failover.service` runs `/usr/local/sbin/wan_failover.py` continuously as root.
Both healthy WANs retain the existing random 50/50 connection assignment. Five
matching observations select fiber-only, cable-only, or even split. When both
WANs fail, the script retains the last policy and keeps probing.

HTTPS probes are bound to each WAN interface. DNS uses the router's configured
resolver, not a separate resolver per WAN. Checks run sequentially, targeting a
one-second interval; timeouts extend that interval. WireGuard recovery refreshes
`vpn.voegele.me:51871` and clears stale UDP connection state without restarting
`wg-quick`. Established connections using a failed public IP may break.

## Requirements

On the router, install Python 3, iproute2, nftables, conntrack-tools,
wireguard-tools, iputils, and ca-certificates. No pip dependencies are needed.
The script checks commands and CA certificates before monitoring starts,
including in dry-run mode.

The script assumes the current router interfaces, routing tables, nftables WAN
assignment chains, and WireGuard peer configuration. Routing-rule priority 90
is reserved for its runtime single-WAN override. Changes are not persisted to
networkd or `/etc/nftables.conf`; the service reconciles after boot or reloads.

## Deployment

Use the repository's deployment mechanism to install the host files, or install
only these files from the repository root on `chadrouter.lan`:

```sh
sudo install -m 755 chadrouter.lan/usr/local/sbin/wan_failover.py /usr/local/sbin/wan_failover.py
sudo install -m 644 chadrouter.lan/etc/systemd/system/wan-failover.service /etc/systemd/system/wan-failover.service
sudo systemctl daemon-reload
sudo python3 /usr/local/sbin/wan_failover.py --dry-run
```

Stop the dry run with Ctrl-C before enabling the service:

```sh
sudo systemctl enable --now wan-failover.service
journalctl -u wan-failover.service -f
```

The script also keeps rotating logs at `/var/log/wan-failover.log`.
`network-online.target` orders startup but does not guarantee Internet access.
Check `systemd-networkd-wait-online` settings: a disconnected WAN should not
unnecessarily delay startup. This unit does not require both WANs to be healthy.

## Verification

```sh
python3 -m unittest discover -s tests -p 'test_wan_failover.py' -v
systemd-analyze verify chadrouter.lan/etc/systemd/system/wan-failover.service
```

The initial 35-second router dry run verified both WANs healthy, correct split
policy detection, debounce, and VPN reachability. It did not exercise policy
writes. Before relying on automatic failover, test modem disconnection and
reconnection in both orders, a total outage, and restoration to even split.
Verify that probes can detect a recovered WAN while single-WAN policy is active.
Verify public service access externally, not through LAN split DNS.

## Stopping and rollback

Stopping the service leaves the last routing/firewall policy intact. To restore
the repository's static even-split configuration on the router:

```sh
sudo systemctl disable --now wan-failover.service
sudo nft -f /etc/nftables.conf
# Remove only this script's priority-90 override, if present:
ip -4 rule show
sudo ip -4 rule del priority 90 table fiber  # if the override selects fiber
sudo ip -4 rule del priority 90 table cable  # if the override selects cable
```

Do not flush conntrack globally. Existing connections may require reconnection
after a WAN change or rollback.
