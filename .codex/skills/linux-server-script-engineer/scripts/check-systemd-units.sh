#!/usr/bin/env bash
set -uo pipefail

emit() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"; }

if (($# != 1)) || [[ ! -e "$1" ]]; then
    printf 'usage: %s <unit-file-or-directory>\n' "${0##*/}" >&2
    exit 2
fi

target="$1"
units=()
failures=0
if [[ -f "$target" ]]; then
    units+=("$target")
else
    while IFS= read -r -d '' unit; do units+=("$unit"); done < <(
        find "$target" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) -not -path '*/.git/*' -print0
    )
fi

if ((${#units[@]} == 0)); then
    emit SKIP discovery "$target" 'no systemd unit files found'
    exit 0
fi

for unit in "${units[@]}"; do
    if command -v systemd-analyze >/dev/null 2>&1; then
        if systemd-analyze verify "$unit" >/dev/null 2>&1; then
            emit PASS systemd-verify "$unit" 'unit verified'
        else
            emit FAIL systemd-verify "$unit" 'inspect systemd-analyze output on stderr'
            systemd-analyze verify "$unit" >&2 || true
            failures=$((failures + 1))
        fi
    else
        emit SKIP systemd-verify "$unit" 'systemd-analyze unavailable'
    fi

    while IFS= read -r line; do
        command="${line#*=}"
        command="${command#-}"
        command="${command%% *}"
        if [[ "$command" == */* && "$command" != /* ]]; then
            emit WARN execstart-path "$unit" "relative path in $line"
        fi
    done < <(grep -E '^Exec(Start|StartPre|StartPost)=' "$unit" 2>/dev/null || true)

    if grep -qE '^Environment(File)?=.*(TOKEN|PASSWORD|SECRET|KEY)=' "$unit" 2>/dev/null; then
        emit WARN inline-secret "$unit" 'possible secret embedded in unit environment'
    fi
done

emit PASS discovery "$target" "${#units[@]} unit file(s) inspected"
((failures == 0))
