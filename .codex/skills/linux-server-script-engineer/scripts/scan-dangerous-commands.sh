#!/usr/bin/env bash
set -uo pipefail

emit() { printf 'WARN\t%s\t%s:%s\t%s\n' "$1" "$2" "$3" "$4"; }

if (($# != 1)) || [[ ! -e "$1" ]]; then
    printf 'usage: %s <shell-file-or-directory>\n' "${0##*/}" >&2
    exit 2
fi

target="$1"
self="$(cd "${0%/*}" 2>/dev/null && pwd)/${0##*/}"
files=()
if [[ -f "$target" ]]; then
    files+=("$target")
else
    while IFS= read -r -d '' file; do files+=("$file"); done < <(
        find "$target" -type f -name '*.sh' -not -path '*/.git/*' -print0
    )
fi

scan_pattern() {
    local check="$1" regex="$2" advice="$3" file line_no text absolute
    for file in "${files[@]}"; do
        absolute="$(cd "${file%/*}" 2>/dev/null && pwd)/${file##*/}"
        [[ "$absolute" == "$self" ]] && continue
        while IFS=: read -r line_no text; do
            [[ -n "$line_no" ]] || continue
            emit "$check" "$file" "$line_no" "$advice"
        done < <(LC_ALL=C grep -nE -- "$regex" "$file" 2>/dev/null || true)
    done
}

scan_pattern remote-pipe '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh([[:space:]]|$)' 'download, verify, then execute a local file'
scan_pattern recursive-delete '(^|[;&|[:space:]])rm[[:space:]]+(-[^[:space:]]*)?r[^[:space:]]*f|(^|[;&|[:space:]])rm[[:space:]]+-f[^[:space:]]*r' 'resolve and validate the exact target before recursive deletion'
scan_pattern eval '(^|[;&|[:space:]])eval[[:space:]]' 'prefer arrays and allowlisted operations'
scan_pattern world-writable 'chmod[[:space:]]+(-R[[:space:]]+)?0?777([[:space:]]|$)' 'use the narrowest ownership and mode'
scan_pattern deprecated-apt 'apt-key|force-yes' 'use Signed-By keyrings and safe APT options'
scan_pattern automatic-removal 'apt(-get)?[^#\n]*(autoremove[^#\n]*(-y|--yes)|(-y|--yes)[^#\n]*autoremove)' 'simulate and review removals separately'
scan_pattern firewall-reset 'ufw[[:space:]]+--force[[:space:]]+reset|ufw[[:space:]]+reset' 'prefer minimal rules; require backup and access rollback'
scan_pattern reboot '(^|[;&|[:space:]])(reboot|shutdown[[:space:]]+-r|systemctl[[:space:]]+reboot)([[:space:]]|$)' 'make reboot explicit and opt-in'
scan_pattern in-place-config 'sed[[:space:]][^#\n]*-i[^#\n]*/etc/' 'back up, render, validate, and install atomically where possible'
scan_pattern config-append '>>[[:space:]]*/etc/' 'prove idempotency and avoid duplicate managed lines'

exit 0
