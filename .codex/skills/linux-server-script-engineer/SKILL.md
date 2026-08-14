---
name: linux-server-script-engineer
description: Audit, debug, design, modify, test, deploy, and maintain Bash or POSIX shell scripts that administer Linux servers. Use for installers, update scripts, systemd units and timers, Debian or Ubuntu APT/dpkg operations, SSH, UFW/nftables, networking, DNS, proxy/VPN/Xray services, permissions, remote rollouts, idempotency, rollback, or shell supply-chain safety. Also use when reviewing dangerous commands such as rm, curl or wget pipelines, sed -i, chmod/chown, sudo, systemctl, apt, dpkg, iptables, nft, ufw, reboot, or package removal. Do not use for tiny shell snippets with no server or operational impact.
---

# Linux Server Script Engineer

Engineer server scripts as recoverable operational changes, not as isolated text edits. Preserve the user's interactive workflow unless a CLI migration is explicitly requested.

## Start with the task boundary

1. Read repository guidance and the actual scripts before proposing changes.
2. Classify the request as audit, diagnosis, implementation, deployment, or monitoring.
3. Keep audits and diagnoses read-only unless the user also authorizes a fix.
4. Distinguish the local workstation, repository, test VM, staging host, and production host.
5. Identify the target shell, distribution/version, init system, architecture, privilege model, and recovery access from evidence. Do not infer them from a filename.
6. List the state that may change: packages, repositories, keys, users, files, permissions, services, firewall, routes, DNS, kernels, bootloader, and reboot.

For XanMod, BBR, qdisc, kernel, bootloader, or broad TCP tuning, also read the repository's `xanmod-operations` skill and its current official sources.

## Run the read-only baseline

Run the bundled auditors before editing when the tools are compatible with the current environment:

```bash
bash scripts/audit-shell-project.sh <repo-or-script>
bash scripts/check-systemd-units.sh <repo-or-unit-directory>
bash scripts/verify-installer-contract.sh <repo-or-script>
```

Treat their output as evidence and heuristics:

- `PASS`: the named check ran and passed.
- `WARN`: inspect manually; do not report it as a confirmed defect.
- `FAIL`: a deterministic check failed, such as shell syntax.
- `SKIP`: a required checker or applicable artifact was unavailable.

Never let an audit script modify the target.

## Follow the engineering loop

### 1. Detect and inspect

- Inventory scripts, sourced files, units, config templates, tests, and download endpoints.
- Run `bash -n` for Bash files and ShellCheck when installed.
- Trace function entry points, traps, subshells, pipelines, exit statuses, temporary files, and cleanup.
- Inspect existing remote state before changing it. For access failures, prove reachability and routing before blaming credentials.
- Read the relevant reference before changing a specialized subsystem.

### 2. Reproduce and explain

- Capture the exact command, stderr, exit code, environment, and changed state.
- Minimize the failing path and form one falsifiable root-cause hypothesis at a time.
- Do not patch several speculative causes together.
- For interrupted installers, determine which steps already committed before rerunning anything.

### 3. Design the transaction

Use this order:

```text
detect -> inspect -> compare -> backup -> modify -> validate -> activate -> verify -> commit
                                      \-> rollback on failure
```

- Prefer minimal edits over resets or wholesale replacement.
- Preserve file ownership, modes, ACLs, and symlink semantics.
- Back up before the first mutation and record the exact backup path.
- Define rollback before package removal, firewall, SSH, networking, kernel, bootloader, or service changes.
- Make reboots explicit and opt-in.
- Keep a known-good kernel and console path for kernel work.

### 4. Implement safely

- Quote expansions unless intentional splitting is documented and tested.
- Avoid `eval`; use arrays for commands and validate all interactive input.
- Use `mktemp -d` and a cleanup trap for temporary state.
- Prefer atomic render-validate-install for configuration files.
- Validate daemon configuration before reload/restart.
- Prefer reload when supported and adequate.
- Make repeated runs converge instead of duplicating repositories, config lines, users, units, or rules.
- Do not require every lifecycle verb for a small single-purpose script; explicitly select the supported lifecycle contract.

### 5. Verify in layers

Use the strongest safe layer available and report the exact layer reached:

1. syntax and static analysis;
2. pure-function or fixture tests;
3. disposable container where systemd/network behavior is not required;
4. VM/VPS with recovery console;
5. live workload and reboot persistence.

After activation, check the daemon's config validator, service state, fresh journal, ports, routes, DNS, firewall, and an end-to-end functional request. Test rollback separately when risk warrants it. Never describe static checks as a live-system test.

## Preserve access and secrets

- Before firewall or SSH changes, detect the actual listening/current connection port, client address, existing rules, and console availability.
- Keep the current session open and require a second successful SSH session before committing access-control changes.
- Do not automatically reset UFW/nftables when a minimal rule change is sufficient.
- Do not log passwords, tokens, private keys, or full proxy URLs containing credentials.
- When the user explicitly needs proxy credentials visible for copying, show them in the interactive terminal but keep them out of general logs and process arguments where possible.
- Store persistent secret-bearing configuration with the narrowest usable ownership and mode, normally `0600`.

## Route to references

- Read [bash-semantics.md](references/bash-semantics.md) for quoting, arrays, pipelines, `set -e`, traps, temp files, and ShellCheck.
- Read [debian-ubuntu-packages.md](references/debian-ubuntu-packages.md) for APT/dpkg, repositories, keys, updates, removals, and kernels.
- Read [systemd-services.md](references/systemd-services.md) for units, timers, validation, activation, logs, and rollback.
- Read [networking-diagnostics.md](references/networking-diagnostics.md) for ports, routes, DNS, interfaces, listeners, and connectivity evidence.
- Read [firewall-and-ssh-safety.md](references/firewall-and-ssh-safety.md) before modifying UFW/nftables/iptables or OpenSSH.
- Read [installer-lifecycle.md](references/installer-lifecycle.md) for idempotency, repair, update, uninstall, state, and atomic config changes.
- Read [supply-chain.md](references/supply-chain.md) for downloads, releases, checksums, signatures, archives, Git mirrors, and installers fetched from the network.
- Read [live-server-testing.md](references/live-server-testing.md) before remote mutation, service disruption, network changes, reboot, or production rollout.
- Refresh URLs and version-dependent claims from [official-sources.md](references/official-sources.md).

## Decide when Bash is no longer enough

Keep a short, host-local installer in Bash. Propose a durable CLI only when the project needs reusable subcommands, structured output, stable configuration/auth, cross-repository installation, or testable libraries. Preserve an interactive menu as a front end when that is the user's preferred interface.

## Complete with evidence

Report confirmed root cause or implemented behavior, files and systems changed, backup and rollback locations, exact checks and results, live-test depth, remaining risks, and Git status. Do not say “done” while required live verification remains; say “implemented and locally verified; live test required.”
