# Official XanMod sources

Check these sources live before every package or compatibility recommendation. Record the access date and do not copy current version numbers into permanent workflow logic.

## Installation and package matrix

- Project and APT repository instructions: https://xanmod.org/
- Official download host, signing key, repository package, and psABI checker: https://dl.xanmod.org/
- Official psABI check script: https://dl.xanmod.org/check_x86-64_psabi.sh
- Official APT repository: http://deb.xanmod.org/

The project page is authoritative for currently supported distribution codenames, MAIN/LTS/RT releases, psABI package families, installation commands, external-module warning, and verification with `/proc/version`.

## Source and release evidence

- Current source tree: https://gitlab.com/xanmod/linux
- Historical GitHub mirror notice: https://github.com/xanmod/linux
- Official BBR project and v3 material: https://github.com/google/bbr

Use XanMod release/package evidence to establish what the distributed kernel includes. Use upstream BBR material for algorithm details, not for claiming that a particular installed package is active.

## Refresh checklist

1. Open the project page and record current MAIN, LTS, and RT branches.
2. Record supported Debian/Ubuntu-derived codenames.
3. Record the currently published metapackage matrix for x64v1/v2/v3.
4. Check the explicit DKMS compatibility warning.
5. Fetch the current psABI script before reproducing its logic.
6. Query the live APT repository from the target system before installation.
7. Compare all findings with `install_xanmod.sh`; flag drift rather than silently trusting repository documentation.

## Current review snapshot

Checked 2026-08-13. The official page showed MAIN 7.1, LTS 6.18, and RT 6.18, while this repository README still described 6.14 and 6.15. This snapshot is evidence of documentation drift, not a permanent version recommendation; refresh it on the next task.
