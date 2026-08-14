# Firewall and SSH safety

## Before changing access

- Determine whether the current session is SSH and capture its client/server addresses and actual server port from `SSH_CONNECTION`.
- Inspect `sshd -T`, listeners, UFW status, and the nftables ruleset.
- Confirm a provider/hypervisor console or another recovery route.
- Preserve the current session and prepare a second session for verification.
- Back up `/etc/ssh` or the changed files and the complete applicable firewall configuration before mutation.

Prefer a minimal firewall change. Resetting UFW or replacing an nftables ruleset requires explicit intent, a full backup, validation, and rollback. Validate IP/CIDR/port input with a real parser rather than a loose regex.

Allow the actual SSH port before enabling a deny-by-default firewall. When restricting by source, include the observed current client address only if it represents the intended stable source/NAT; explain dynamic-address risk.

## OpenSSH transaction

1. Validate at least one usable authorized public key with `ssh-keygen`.
2. Use a dedicated drop-in when supported; account for OpenSSH's first-obtained-value behavior and include order.
3. Run `sshd -t` and inspect effective values with `sshd -T`.
4. Reload rather than restart when possible.
5. Keep the original connection open.
6. Prove a second key-authenticated login.
7. Roll back immediately if verification fails or is not confirmed.

Do not disable password or keyboard-interactive authentication before proving key access. Do not remove TCP forwarding mechanically when the server is intentionally used for SSH tunnels.

## Official sources

- Ubuntu firewall guide: https://documentation.ubuntu.com/server/how-to/security/firewalls/
- Ubuntu OpenSSH guide: https://documentation.ubuntu.com/server/how-to/security/openssh-server/
- sshd_config(5): https://man.openbsd.org/sshd_config
- nftables documentation: https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
