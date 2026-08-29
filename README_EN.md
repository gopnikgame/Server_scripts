# Server Scripts Manager

[Русский](README.md) · [English](README_EN.md)

A collection of interactive Bash modules for initial setup and maintenance of Ubuntu 24.04 LTS servers. On every normal run, the launcher checks `main`, downloads the launcher and modules as one consistent snapshot, runs `bash -n`, and activates the update atomically only after validation succeeds.

![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white)
![License MIT](https://img.shields.io/badge/license-MIT-blue)

## Quick start

Run as `root`. These commands download the file before executing it; they do not use `curl | bash`.

### curl

```bash
curl -fL --retry 3 -o server_launcher.sh \
  https://raw.githubusercontent.com/gopnikgame/Server_scripts/main/server_launcher.sh \
  && bash server_launcher.sh
```

### wget

```bash
wget --https-only -O server_launcher.sh \
  https://raw.githubusercontent.com/gopnikgame/Server_scripts/main/server_launcher.sh \
  && bash server_launcher.sh
```

[Download the launcher directly](https://raw.githubusercontent.com/gopnikgame/Server_scripts/main/server_launcher.sh)

> If GitHub is blocked on the target server, first use `setup_proxy.sh` through another reachable server or an existing SSH/VLESS connection.

## Modules

| Module | Purpose |
|---|---|
| `ubuntu_pre_install.sh` | Initial Ubuntu setup: packages, SSH, UFW, DNSCrypt, IPv6 |
| `setup_proxy.sh` | Temporary HTTP/SOCKS5 servers and HTTP, SOCKS5, SSH SOCKS, VLESS clients |
| `install_xanmod.sh` | XanMod LTS, boot verification, and a TCP profile for VLESS/REALITY |
| `bbr_info.sh` | BBR, qdisc, Xray, and network-limit diagnostics |
| `snapfile.sh` | Create, resize, and remove a swap file |
| `speed_dns.sh` | DNS latency, DNSSEC, TCP/53, and route checks |
| `auto_update_vps.sh` | Safe APT upgrades and a systemd timer schedule |

## Proxy Manager

The same `setup_proxy.sh` is used in two roles:

- on a reachable server, it starts a temporary HTTP/SOCKS5 service or permits SSH TCP forwarding for one user and client CIDR;
- on the blocked machine, it consumes the connection bundle, a ready HTTP proxy, SSH SOCKS, or an existing `vless://` link;
- cleanup removes only resources owned by the module and restores the previous proxy files.

VLESS is client-only. The module never creates, modifies, or removes VLESS servers. WireGuard is intentionally omitted because HTTP, SOCKS5, and SSH SOCKS cover the intended temporary-access workflows.

## Updating the launcher

```bash
server_launcher.sh --status       # show local snapshot state
server_launcher.sh --refresh      # fetch the latest main snapshot and exit
server_launcher.sh --no-refresh   # open the menu without a network check
```

A normal `server_launcher.sh` run also checks for updates. If `raw.githubusercontent.com` is unavailable, the launcher uses a `codeload.github.com` archive for the same commit SHA. A full commit SHA can be pinned:

```bash
SERVER_SCRIPTS_COMMIT=<40-character-SHA> server_launcher.sh --refresh
```

## Safety and rollback

- Ubuntu 24.04 LTS and root access are required. Keep console access available for SSH, UFW, or kernel changes.
- SSH configuration is validated with `sshd -t`; UFW and system files are backed up before modification.
- Xray is downloaded from the official release, SHA-256 verified, and tested before activation.
- Proxy credentials are shown only in an interactive TTY and stored in restricted files.
- Kernel installation preserves a working Ubuntu kernel; reboot remains a separate explicit action.

## Useful commands

```bash
tail -f /var/log/server-scripts/server-scripts.log
tail -f /var/log/server-scripts/setup_proxy.log
journalctl -u server-scripts-proxy-server.service -f
journalctl -u server-scripts-proxy-client.service -f
journalctl -u server-scripts-update.service -f
```

## Repository checks

```bash
bash .codex/skills/linux-server-script-engineer/scripts/self-test.sh
bash .codex/skills/linux-server-script-engineer/scripts/audit-shell-project.sh .
bash tests/test_setup_proxy.sh
```

The `tests/live_test_*.sh` scenarios are intended only for a disposable Ubuntu VM with console access and a snapshot.

## License

[MIT](LICENSE) · [GitHub Issues](https://github.com/gopnikgame/Server_scripts/issues)
