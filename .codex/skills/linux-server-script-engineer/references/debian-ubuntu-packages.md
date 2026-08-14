# Debian and Ubuntu package operations

## Inspect first

```bash
. /etc/os-release
dpkg --print-architecture
dpkg --audit
apt-get check
apt-mark showhold
apt-cache policy <package>
df -h / /boot
```

Confirm the distribution codename against the repository's current published support. Do not infer compatibility only from `ID=ubuntu` or `ID=debian`.

## Safe package workflow

1. Inventory installed, held, manual, kernel, DKMS, and repository state.
2. Refresh indexes and capture repository errors.
3. Simulate the exact operation with `apt-get -s`.
4. Inspect `Inst`, `Remv`, downgrades, held packages, and essential components.
5. Back up package selections and changed repository/key files.
6. Apply the narrowest operation.
7. Run `dpkg --audit`, `apt-get check`, service checks, and workload verification.

`apt-get upgrade` does not remove installed packages. `dist-upgrade` may remove packages to resolve dependencies. Treat `autoremove` as an independent removal operation: preview it and protect the running and last known-good kernels. Never use deprecated `--force-yes`.

Use repository-specific keyrings and `Signed-By`; do not introduce `apt-key`. Verify key fingerprints from an independent official channel when the publisher provides them.

Do not combine ordinary upgrade, full upgrade, autoremove, repository migration, and reboot into one implicit scheduled action.

## Official sources

- apt-get(8): https://manpages.debian.org/unstable/apt/apt-get.8.en.html
- apt-secure(8): https://manpages.debian.org/unstable/apt/apt-secure.8.en.html
- Debian repository format: https://wiki.debian.org/DebianRepository/Format
- Ubuntu package management: https://documentation.ubuntu.com/server/how-to/software/package-management/
