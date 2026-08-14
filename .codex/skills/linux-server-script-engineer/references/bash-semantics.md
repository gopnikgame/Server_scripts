# Bash semantics and static checks

Read this for quoting, expansions, arrays, pipelines, `set -e`, traps, temporary files, sourced scripts, ShellCheck findings, signals, and exit-code design.

## Required reasoning

- Identify the real interpreter from the shebang and invocation. `sh file.sh` ignores a Bash shebang.
- Quote parameter, command, and arithmetic results unless splitting/globbing is deliberate and tested.
- Use arrays for command arguments. Do not construct a command string and pass it to `eval`.
- Treat `IFS`, `read`, globbing, filenames beginning with `-`, empty arrays, and newline-containing values as input boundaries.
- Use `printf` for data. Do not depend on implementation-specific `echo -e` behavior in reusable tools.
- Check pipeline semantics. Without `pipefail`, a failed producer may be hidden by a successful consumer.
- Do not assume `set -e` is exception handling. Its behavior changes in conditionals, `&&`/`||` lists, pipelines, command substitutions, functions, and subshells.
- Capture `$?` immediately. A later command overwrites it.
- Make cleanup traps preserve the original exit code. Avoid recursive `ERR` traps.
- Create temporary directories with `mktemp -d`, restrictive modes, and a narrow cleanup target.
- Make library-style scripts sourceable by guarding the entry point with `[[ ${BASH_SOURCE[0]} == "$0" ]]`.
- Use `--` before untrusted positional paths when the command supports it.

## Baseline checks

```bash
bash -n script.sh
shellcheck script.sh
```

Do not silence ShellCheck globally. Suppress one finding next to the intentional construct and explain why.

## Official sources

- GNU Bash manual: https://www.gnu.org/software/bash/manual/bash.html
- ShellCheck project and rule links: https://www.shellcheck.net/
- POSIX shell command language: https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html
