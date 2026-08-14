#!/usr/bin/env bash
set -uo pipefail

emit() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"; }

if (($# != 1)) || [[ ! -f "$1" ]]; then
    printf 'usage: %s <shell-file>\n' "${0##*/}" >&2
    exit 2
fi

file="$1"
failures=0
interpreter=bash
first_line="$(IFS= read -r line < "$file" && printf '%s' "$line")"
[[ "$first_line" == *'/sh'* && "$first_line" != *bash* ]] && interpreter=sh

if "$interpreter" -n "$file" 2>/dev/null; then
    emit PASS syntax "$file" "$interpreter -n"
else
    emit FAIL syntax "$file" "$interpreter -n failed"
    "$interpreter" -n "$file" >&2 || true
    failures=$((failures + 1))
fi

if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -x "$file" >/dev/null 2>&1; then
        emit PASS shellcheck "$file" 'no findings'
    else
        emit WARN shellcheck "$file" 'inspect ShellCheck output on stderr'
        shellcheck -x "$file" >&2 || true
    fi
else
    emit SKIP shellcheck "$file" 'shellcheck unavailable'
fi

if command -v iconv >/dev/null 2>&1; then
    if iconv -f UTF-8 -t UTF-8 "$file" >/dev/null 2>&1; then
        emit PASS utf8 "$file" 'valid UTF-8'
    else
        emit FAIL utf8 "$file" 'invalid UTF-8'
        failures=$((failures + 1))
    fi
else
    emit SKIP utf8 "$file" 'iconv unavailable'
fi

if LC_ALL=C grep -q $'\r$' "$file" 2>/dev/null; then
    emit WARN line-endings "$file" 'CRLF detected; verify target interpreter behavior'
else
    emit PASS line-endings "$file" 'no CRLF detected'
fi

((failures == 0))
