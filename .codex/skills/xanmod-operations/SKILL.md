---
name: xanmod-operations
description: Inspect, install, upgrade, validate, troubleshoot, or remove XanMod kernels on Debian-family systems. Use for XanMod APT repositories and keys, x86-64 psABI package selection, MAIN/LTS/RT choices, BBRv3, qdisc and sysctl tuning, GRUB or other bootloaders, DKMS compatibility, rollback planning, and maintenance of install_xanmod.sh. Do not use for unrelated stock-kernel administration.
---

# XanMod Operations

Ground every version, codename, package, and feature claim in current official sources. Read [references/official-sources.md](references/official-sources.md) before changing installation logic or recommending a package.

## Workflow

1. Start read-only. Capture `/etc/os-release`, `uname -m`, `uname -r`, virtualization, boot mode, active bootloader, free `/boot` and `/` space, installed kernels, held packages, DKMS state, and Secure Boot state.
2. Confirm that the distribution codename is currently listed by XanMod. Do not infer support from `ID=debian` or `ID=ubuntu` alone.
3. Determine x86-64 psABI with the current official check script or equivalent read-only CPU-feature checks. Never select a higher level than the CPU exposes. Remember that x64v1 is limited to package families currently published for it.
4. Query the configured APT repository with `apt-cache policy` and `apt-cache show` before choosing a metapackage. Do not hard-code kernel branch numbers from README text.
5. Choose MAIN, LTS, or RT from workload and compatibility evidence. Prefer LTS where third-party DKMS support or conservative server operation matters. Treat EDGE as unavailable unless the current repository actually publishes it.
6. Before installation, inventory DKMS consumers such as NVIDIA, ZFS, VirtualBox, VMware, WireGuard add-ons, and vendor drivers. Surface unsupported modules as a blocker or explicit risk.
7. Back up changed APT, sysctl, and bootloader files. Preserve at least one known-good bootable kernel and a recovery-console path.
8. Use the official `signed-by` keyring pattern. Download the key over HTTPS, inspect its fingerprint when possible, and never use `apt-key`.
9. Install the selected metapackage without removing the running kernel. Do not reboot automatically unless the user explicitly authorizes it.
10. After reboot, verify `uname -r`, `/proc/version`, package state, DKMS builds, failed services, network reachability, `tcp_available_congestion_control`, active congestion control, and qdisc.
11. Keep BBR selection separate from broad TCP tuning. Apply only settings justified by the workload and host resources; do not label arbitrary buffer or timeout values as XanMod defaults.
12. Provide rollback commands for the detected bootloader and package family before risky work.

## Repository maintenance

When editing `install_xanmod.sh`:

- Compare its repository/key commands, supported codenames, and package names with the official page.
- Replace stale version menus with repository-driven discovery where practical.
- Keep detection and plan modes usable without root and without mutations.
- Avoid assuming systemd, GRUB, BIOS, or unrestricted `/boot` space.
- Keep network/proxy credentials out of logs and persistent files.
- Make reboots opt-in and state-file continuation idempotent.
- Add shell syntax checks and fixture-based tests for OS, psABI, package selection, and failure paths.
- Mark behavior requiring a live VM or bare-metal test explicitly.

## Safety boundaries

- Treat kernel install, repository changes, sysctl writes, bootloader updates, service changes, package removal, and reboot as mutations requiring clear authorization.
- Never purge the running kernel or the last known-good kernel.
- Do not claim BBRv3 from the string `bbr` alone; use the running XanMod build and available project/kernel evidence.
- Do not use `modinfo tcp_bbr` as the only check because BBR may be built into the kernel.
- Do not assume a successful package installation means the new kernel booted.
- Require live-system testing for installer changes that touch boot, networking, DKMS, or reboot continuation.

## Deliverable

Separate confirmed facts, risks, proposed changes, commands, verification, and rollback. Cite the exact official URLs used and include the date checked because the XanMod release and package matrix changes over time.
