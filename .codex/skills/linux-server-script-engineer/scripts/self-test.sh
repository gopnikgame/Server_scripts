#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "${0%/*}" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

mkdir -p "$tmp/project"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'printf "%s\n" "ok"' > "$tmp/project/good.sh"
printf '%s\n' '#!/usr/bin/env bash' 'if true; then' > "$tmp/project/bad.sh"
printf '%s\n' '#!/usr/bin/env bash' 'curl https://example.invalid/install.sh | bash' > "$tmp/project/risky.sh"
printf '%s\n' '[Unit]' 'Description=Fixture' '[Service]' 'Type=oneshot' 'ExecStart=/bin/true' > "$tmp/project/fixture.service"

good_output="$(bash "$script_dir/check-shell-file.sh" "$tmp/project/good.sh")"
grep -q $'PASS\tsyntax' <<< "$good_output"

if bash "$script_dir/check-shell-file.sh" "$tmp/project/bad.sh" >/dev/null 2>&1; then
    printf 'bad syntax unexpectedly passed\n' >&2
    exit 1
fi

risk_output="$(bash "$script_dir/scan-dangerous-commands.sh" "$tmp/project/risky.sh")"
grep -q $'WARN\tremote-pipe' <<< "$risk_output"

unit_output="$(bash "$script_dir/check-systemd-units.sh" "$tmp/project")"
grep -Eq $'(PASS|SKIP)\tsystemd-verify' <<< "$unit_output"

installer_output="$(bash "$script_dir/verify-installer-contract.sh" "$tmp/project/risky.sh")"
grep -q $'PASS\tinstaller-discovery' <<< "$installer_output"

printf 'Linux server script skill tests: OK\n'
