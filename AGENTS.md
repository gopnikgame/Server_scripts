# Repository guidance

For XanMod kernel, BBR, qdisc, sysctl, bootloader, or `install_xanmod.sh` work, use `.codex/skills/xanmod-operations/SKILL.md` and refresh its official sources before making version or package claims.

Treat kernel installation, package removal, repository changes, sysctl writes, bootloader changes, service changes, and reboot as live-system mutations. Preserve a known-good kernel and provide verification and rollback. Installer changes affecting boot or networking require explicit live-system testing.
