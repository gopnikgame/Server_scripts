# Repository guidance

For Bash installers, update scripts, systemd units, Debian/Ubuntu packages, SSH, UFW/nftables, networking, DNS, proxy/VPN services, remote rollout, or shell supply-chain work, use `.codex/skills/linux-server-script-engineer/SKILL.md` and load only the references relevant to the task.

For XanMod kernel, BBR, qdisc, sysctl, bootloader, or `install_xanmod.sh` work, use both the Linux server script skill and `.codex/skills/xanmod-operations/SKILL.md`; refresh official sources before making version or package claims.

Treat kernel installation, package removal, repository changes, sysctl writes, bootloader changes, service changes, and reboot as live-system mutations. Preserve a known-good kernel and provide verification and rollback. Installer changes affecting boot or networking require explicit live-system testing.
