# Live server testing and rollout

## Evidence ladder

Label results precisely:

- static: parsing, ShellCheck, unit-template validation;
- fixture: pure logic and generated config checked locally;
- container: package/filesystem behavior without reliable host init/network semantics;
- VM/VPS: real systemd, firewall, kernel, boot, and network behavior;
- workload: real proxy/VPN/application traffic and client behavior;
- persistence: reboot and repeated-run verification.

## Remote mutation protocol

1. Confirm the exact host identity, OS, role, and whether it is test or production.
2. Establish reachability and recovery-console access.
3. Capture pre-change packages, files, permissions, services, ports, routes, DNS, firewall, disk, memory, and failed units relevant to the task.
4. Back up before mutation and print the path.
5. Keep one control connection open; use a second connection for access changes.
6. Apply one bounded stage.
7. Validate configuration before activation.
8. Read fresh logs and perform a functional check.
9. Roll back on failed gates; do not continue into unrelated stages.
10. Reboot only with explicit authorization, then reconnect and repeat verification.

Do not deploy secrets copied from repository examples. Do not echo secrets into general logs. Use the configured credential mechanism and avoid retaining retrieved credentials.

For high-risk changes, state stop points before executing: package/repository change, firewall/SSH activation, kernel selection, reboot, and cleanup/removal.

## Handoff

Record host, timestamp, backup paths, commands/checks, pre/post versions, service status, functional result, reboot result, rollback test, and anything still unverified. A successful SSH command is not proof that a proxy/VPN workload works.
