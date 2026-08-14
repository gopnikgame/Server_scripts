#!/usr/bin/env bash
set -uo pipefail

emit() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"; }

if (($# != 1)) || [[ ! -e "$1" ]]; then
    printf 'usage: %s <installer-file-or-directory>\n' "${0##*/}" >&2
    exit 2
fi

target="$1"
files=()
if [[ -f "$target" ]]; then
    files+=("$target")
else
    while IFS= read -r -d '' file; do files+=("$file"); done < <(
        find "$target" -type f \( -iname '*install*.sh' -o -iname '*setup*.sh' -o -iname '*update*.sh' -o -iname '*launcher*.sh' \) \
            -not -path '*/.git/*' -not -path '*/tests/*' -not -path '*/.codex/skills/*/scripts/*' -print0
    )
fi

if ((${#files[@]} == 0)); then
    emit SKIP discovery "$target" 'no installer-like scripts found'
    exit 0
fi

for file in "${files[@]}"; do
    emit PASS installer-discovery "$file" 'installer-like script selected'
    grep -qiE 'backup|резервн' "$file" || emit WARN backup-contract "$file" 'no obvious backup path; inspect manually'
    grep -qiE 'rollback|restore|откат|восстанов' "$file" || emit WARN rollback-contract "$file" 'no obvious rollback path; inspect manually'
    grep -qiE 'status|doctor|diagnos|провер' "$file" || emit WARN status-contract "$file" 'no obvious status/diagnostic operation'
    grep -qiE 'uninstall|remove_|disable_|удал|отключ' "$file" || emit WARN uninstall-contract "$file" 'no obvious uninstall/disable operation'
    if grep -nE '>>[[:space:]]*/etc/|echo[^#\n]*>>[^#\n]*(\.conf|\.list)' "$file" >/dev/null 2>&1; then
        emit WARN append-idempotency "$file" 'unconditional config append may duplicate state'
    fi
    if grep -nE '(^|[;&|[:space:]])(useradd|groupadd)[[:space:]]' "$file" >/dev/null 2>&1; then
        emit WARN account-idempotency "$file" 'verify account existence before creation'
    fi
done

emit PASS discovery "$target" "${#files[@]} installer-like file(s) inspected"
exit 0
