# Installer lifecycle and idempotency

## Select the contract

Choose and document only the lifecycle operations the component genuinely supports:

- install;
- repeat install;
- update;
- reconfigure;
- repair;
- status/doctor;
- uninstall;
- rollback.

A small one-shot helper need not implement all verbs. A persistent server manager should expose enough state and recovery operations to be operated without editing its source.

## Convergence rules

Repeated execution must not duplicate repository entries, keys, users, groups, config blocks, cron jobs, systemd units, firewall rules, or secrets. Inspect current state and compare desired state before mutation.

Prefer these patterns:

- render complete managed fragments instead of repeatedly appending;
- use dedicated drop-ins instead of rewriting vendor configuration;
- stage a candidate, validate it, then atomically install it;
- preserve unmanaged user content;
- record state only after successful activation;
- keep uninstall bounded to files/resources owned by the installer;
- make repair revalidate reality rather than trusting a stale state file.

Do not use a state file as proof that a service is healthy. Cross-check packages, files, permissions, service state, ports, and a functional request.

## Test matrix

Test clean install, second install, partial/interrupted state, update, invalid input, unavailable network, daemon config failure, rollback, and uninstall-with-user-data. Use fixtures for pure functions and a disposable VM for systemd/firewall/reboot behavior.
