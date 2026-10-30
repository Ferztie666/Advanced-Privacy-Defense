# PPS Lite privacy mode — architecture and safety contract

Status: design and implementation gate. This document does not claim that a system-wide VPN kill switch is implemented.

## Target environment

- Kali Linux guest in VirtualBox.
- Host memory: 8 GiB; start with 2 vCPU and 3–4 GiB guest RAM, then adjust only after measuring host pressure.
- VirtualBox NAT is the default adapter mode. Use bridged networking only for an explicitly authorized LAN lab.
- Workload: authorized web and network security testing.

## Selected design

Use one WireGuard full-tunnel interface managed inside the Kali guest, with a narrowly owned nftables output guard. Do not add Tor-over-VPN, multihop, or per-tool proxy chains to the default path. Keep Tor Browser separate for browsing use cases; it is not a universal transport for scanners, UDP, or Nmap.

The guest's network path is:

Applications -> Linux routing -> WireGuard -> VPN provider egress -> authorized target.

A system-level route/firewall design is required because proxy environment variables and individual scanner flags do not cover every application or protocol.

## Required command contract

- `pps privacy on PROFILE`: preflight the profile and dependencies; refuse unsafe/ambiguous configuration; install a PPS-owned fail-closed guard before bringing up the tunnel; verify tunnel handshake, full-tunnel routes, and egress; roll back only PPS-owned state if activation fails.
- `pps privacy status`: report tunnel/interface, routes, guard presence, DNS resolver, IPv4/IPv6 policy, and last verification. Never print private keys or full config contents.
- `pps privacy check`: perform explicit egress/DNS/IPv6 checks and a controlled fail-closed test. A simple HTTPS success is not sufficient evidence.
- `pps privacy off`: bring the tunnel down while the guard remains in place, then remove only the exact PPS-owned nftables table after confirming the interface is down. If cleanup cannot be proven safe, keep the guard and explain recovery.

## Non-negotiable safety rules

1. Never flush or replace the global nftables ruleset; never alter unrelated tables/chains.
2. Use a uniquely named PPS-owned nftables table and refuse to overwrite it if it already exists unexpectedly.
3. Parse and validate the selected WireGuard profile before changing the system:
   - require a numeric Endpoint address to avoid bootstrap DNS leakage;
   - require a UDP endpoint and valid port;
   - require full-tunnel AllowedIPs for IPv4 and/or IPv6;
   - explicitly block IPv6 outside the tunnel when the profile does not carry IPv6;
   - reject arbitrary PreUp/PostUp/PreDown/PostDown hooks in the first implementation;
   - reject unsupported routing/table directives rather than guessing.
4. Permit only loopback, established return traffic, traffic leaving through the selected WireGuard interface, and the minimum UDP traffic needed to reach the configured VPN endpoint on the physical route.
5. Do not silently fall back to the ordinary network if the tunnel fails. Fail closed.
6. Preserve unrelated routes, resolver settings, and firewall state. Do not overwrite system DNS files or change host networking.
7. Persist only minimal state with restrictive permissions; do not store private keys, full profiles, or secrets in PPS state/logs.
8. Require root privileges for system networking changes and explain exactly what will change before the first activation.
9. Keep proxy-only commands available as a separate, explicitly limited mode. Do not label proxy mode as system-wide protection.
10. Never claim absolute anonymity. The VPN changes network egress; it does not remove account identity, browser fingerprinting, endpoint compromise, traffic correlation, or application-level disclosure.

## Failure and recovery behavior

- If preflight fails: make no network changes.
- If guard installation fails: do not bring up the tunnel.
- If tunnel activation or verification fails: keep the guard active until the tunnel is confirmed down, then remove only PPS-owned state if safe.
- If deactivation fails: leave the guard in place and print manual recovery guidance; never open the network as a convenience fallback.
- On reboot: do not automatically enable privacy mode until explicit opt-in and boot ordering/recovery behavior have been tested.

## Test gates before calling this feature ready

Unit tests must cover profile parsing, malformed/duplicate directives, IPv4-only and dual-stack profiles, endpoint exceptions, command ordering, idempotency, stale state, permission checks, and every rollback path with mocked system commands.

Integration tests in a disposable Kali VM must verify:
- normal network state is unchanged before activation;
- all guest applications use the tunnel while active;
- IPv4 and IPv6 cannot escape outside the tunnel;
- DNS requests do not escape outside the tunnel;
- killing the WireGuard interface/process does not restore direct egress;
- `privacy off` restores connectivity and leaves unrelated firewall tables unchanged;
- reboot and VirtualBox NAT reconnect behavior;
- Burp Suite/browser and representative TCP/UDP network tools behave as expected.

Do not release the feature as production-ready until these tests pass on a real Kali VM and an independent review checks the firewall/routing logic.

## Current implementation boundary

The current PPS branch has proxy-aware process launching and manual WireGuard profile up/down support. It does not yet implement the system-wide guard, full-tunnel verification, DNS/IPv6 leak prevention, or safe one-command ON/OFF session management. A WireGuard profile from a provider is also not available yet. Therefore `pps privacy on` must not be advertised as available until implementation and integration gates above are met.
