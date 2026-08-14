#!/usr/bin/env bash
set -uo pipefail

if (($# != 1)) || [[ ! -e "$1" ]]; then
    printf 'usage: %s <shell-file-or-directory>\n' "${0##*/}" >&2
    exit 2
fi

target="$1"
script_dir="$(cd "${0%/*}" && pwd)"
files=()
failures=0

if [[ -f "$target" ]]; then
    files+=("$target")
else
    while IFS= read -r -d '' file; do files+=("$file"); done < <(
        find "$target" -type f -name '*.sh' -not -path '*/.git/*' -print0
    )
fi

if ((${#files[@]} == 0)); then
    printf 'SKIP\tdiscovery\t%s\tno .sh files found\n' "$target"
    exit 0
fi

for file in "${files[@]}"; do
    if ! bash "$script_dir/check-shell-file.sh" "$file"; then failures=$((failures + 1)); fi
done
bash "$script_dir/scan-dangerous-commands.sh" "$target"

printf 'PASS\tdiscovery\t%s\t%d shell file(s) inspected\n' "$target" "${#files[@]}"
((failures == 0))
