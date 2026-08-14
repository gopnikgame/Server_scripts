# Networking diagnostics

## Prove each layer

Do not reduce “network works” to one ping. Inspect in order:

1. interface/link and addresses;
2. routes and policy rules;
3. local listeners and owning processes;
4. firewall;
5. DNS configuration and resolution;
6. TCP/UDP reachability;
7. TLS/HTTP/application behavior;
8. service and kernel logs.

Useful read-only commands:

```bash
ip -brief link
ip -brief address
ip route show table all
ip rule show
ss -lntup
ss -s
resolvectl status
resolvectl query example.com
dig example.com
curl -v --connect-timeout 10 https://example.com/
journalctl -k --since '10 minutes ago' --no-pager
```

Use `ip route get <address>` to prove the chosen path. Compare IPv4 and IPv6 explicitly. Remember that ICMP may be filtered while TCP works, and DNS success does not prove the target port is reachable.

Before opening a port, identify the listener, bind address, protocol, namespace/container, and existing firewall exposure. For proxy/VPN/Xray changes, test both the local listener and an end-to-end request through the intended path.

Do not apply generic sysctl “optimization” without workload measurements. Capture retransmits, listen drops, queue pressure, latency, CPU, memory, and connection counts before tuning.

## Official sources

- iproute2 repository: https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/
- systemd-resolved: https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html
- ss(8): https://manpages.debian.org/unstable/iproute2/ss.8.en.html
