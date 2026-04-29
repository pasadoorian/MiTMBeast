# Restoring a MITM Beast machine to a normal Linux configuration

When `mitm.sh up` runs, it stops and disables `NetworkManager`,
`systemd-networkd`, and `systemd-resolved`, overwrites `/etc/resolv.conf`,
and inserts iptables rules. `mitm.sh down` releases the interfaces but does
**not** re-enable the system services — that's intentional, since this
toolkit assumes a dedicated host.

When the host is repurposed, use this guide to put it back to a normal
Linux state.

## The easy way

```bash
sudo ./mitm.sh restore
```

The script asks which network manager to re-enable, restores
`/etc/resolv.conf` from the backup made at `up` time, and prints the
remaining manual steps.

For non-interactive use (e.g., automation, ssh-with-no-tty):

```bash
sudo ./mitm.sh restore --manager NetworkManager
sudo ./mitm.sh restore --manager systemd-networkd
sudo ./mitm.sh restore --manager none      # don't touch any service
```

## The manual way

Use this when the script is unavailable, or when you need explicit control.

### 1. Re-enable a network manager

Pick whichever your distro normally uses.

**NetworkManager** (most desktops, Kali, Ubuntu desktop):

```bash
sudo systemctl enable --now NetworkManager
sudo systemctl enable --now systemd-resolved   # NetworkManager uses it for DNS
```

**systemd-networkd** (servers, minimal installs):

```bash
sudo systemctl enable --now systemd-networkd
sudo systemctl enable --now systemd-resolved
```

### 2. Restore `/etc/resolv.conf`

`mitm.sh up` records the original state in one of:

- `/etc/resolv.conf.backup` — original was a regular file
- `/run/mitm-beast/resolv_was_symlink_to` — original was a symlink; this
  file contains the original target path

Restore by hand:

```bash
# If the file backup exists:
sudo mv /etc/resolv.conf.backup /etc/resolv.conf

# If the symlink marker exists:
target=$(cat /run/mitm-beast/resolv_was_symlink_to)
sudo rm /etc/resolv.conf
sudo ln -s "$target" /etc/resolv.conf
sudo rm /run/mitm-beast/resolv_was_symlink_to

# If neither exists (e.g., reboot wiped /run), recreate the standard
# systemd-resolved symlink:
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

### 3. Remove iptables rules

In v1.0, `mitm.sh up` runs `iptables --flush` which wipes everything; on
`down` it does not restore them. The simplest restoration on a dedicated
machine is to flush and let the network manager / firewall service rebuild
its own state on next start:

```bash
sudo iptables --flush
sudo iptables -t nat --flush
```

In v1.1+ (after M1.2), MITM Beast uses dedicated chains (`MITM_NAT_PRE`,
`MITM_NAT_POST`, `MITM_FWD`, `MITM_NTP_PRE`). Remove just those:

```bash
for chain in MITM_NAT_PRE MITM_NAT_POST MITM_NTP_PRE; do
  sudo iptables -t nat -D PREROUTING -j "$chain"  2>/dev/null
  sudo iptables -t nat -D POSTROUTING -j "$chain" 2>/dev/null
  sudo iptables -t nat -F "$chain"                2>/dev/null
  sudo iptables -t nat -X "$chain"                2>/dev/null
done
sudo iptables -D FORWARD -j MITM_FWD 2>/dev/null
sudo iptables -F MITM_FWD            2>/dev/null
sudo iptables -X MITM_FWD            2>/dev/null
```

### 4. Re-enable any user firewall

If you used `ufw`, `firewalld`, or another firewall before MITM Beast,
re-enable it now:

```bash
sudo ufw enable                # ufw
sudo systemctl start firewalld # firewalld
```

### 5. Reboot (recommended)

Easiest sanity check that everything is back to normal:

```bash
sudo reboot
```

After reboot, verify:

- `ip -br addr` — primary interface has an IP
- `cat /etc/resolv.conf` — points where it should
- `ping 1.1.1.1` and `getent hosts kali.org` — network and DNS work
- `sudo iptables -L -n` — no leftover MITM_* chains; firewall as expected
