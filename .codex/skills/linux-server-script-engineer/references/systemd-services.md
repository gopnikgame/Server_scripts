# systemd services and timers

## Inspect

```bash
systemctl cat example.service
systemctl show example.service -p FragmentPath -p DropInPaths -p User -p ExecStart
systemctl is-enabled example.service
systemctl is-active example.service
journalctl -u example.service --since '10 minutes ago' --no-pager
```

Account for vendor units, local copies, drop-ins, generated units, and transient units. Do not edit files under `/usr/lib/systemd/system` or `/lib/systemd/system` when a local unit or drop-in is appropriate.

## Validate and activate

1. Render a candidate to a temporary file.
2. Run `systemd-analyze verify` on the candidate and related units.
3. Run the daemon's own config test.
4. Install atomically with correct ownership/mode.
5. Run `systemctl daemon-reload` only after unit files change.
6. Prefer reload when it applies; otherwise restart with rollback ready.
7. Verify active state, `ExecMainStatus`, restart count, listeners, journal, and functional behavior.

Do not add `Restart=always` mechanically. Match restart policy to long-running, oneshot, timer, and failure semantics. Use `EnvironmentFile` carefully: systemd environment variables are not a secret store, and file permissions still matter.

For timers, inspect both the timer and service. Use `Persistent=true` only when a missed run should execute after downtime. Add randomized delay when fleet-wide synchronization is undesirable. Never hide reboot or destructive cleanup inside a maintenance timer.

## Official sources

- systemd.service: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html
- systemd.timer: https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html
- systemd.unit: https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html
- systemd-analyze: https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html
