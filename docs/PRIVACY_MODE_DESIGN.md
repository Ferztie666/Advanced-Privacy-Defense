# PPS Lite privacy mode — architecture and safety contract

Status: design and implementation gate. This document does not claim that a system-wide VPN kill switch is implemented.

## Target environment

- Kali Linux guest in VirtualBox.
- Host memory: 8 GiB; start with 2 vCPU and 3–4 GiB guest RAM, then adjust only after measuring host pressure.
- VirtualBox NAT is the default adapter mode. Use bridged networking only for an explicitly authorized LAN lab.
- Workload: authorized web and network security testing.

## Selected design

Use one WireGuard full-tunnel interface managed inside the Kali guest, with a narrowly owned nftables output guard. Do not add Tor-over-VPN, multihop, or per-tool proxy chains to the default path. Keep Tor Browser separate for browsing use cases; it is not a universal transport for scanners, UDP, or Nmap.

Applications -> Linux routing -> WireGuard -> VPN provider egress -> authorized target.

A system-level route/firewall design is required because proxy environment variables and individual scanner flags do not cover every application or protocol.

## Provider compatibility

PPS uses standard WireGuard profiles from providers that support WireGuard; it does not create VPN credentials or operate VPN servers.

- IPv4 full-tunnel (0.0.0.0/0) is mandatory.
- IPv6 full-tunnel (::/0) is optional. If absent, the future firewall manager must explicitly block all non-loopback IPv6 egress while privacy mode is active. It must never allow IPv6 to fall back to the physical interface.
- Split-tunnel profiles are rejected in the first release.
- Endpoint must be a numeric unicast IP and UDP port to avoid bootstrap DNS leakage. Private unicast endpoints can be useful for a local VPN gateway; unspecified, multicast, loopback, and link-local endpoints are rejected.
- The profile must be a regular file with mode 0600 or stricter. Arbitrary hooks, DNS directives, routing-table directives, multiple peers, and unknown options are rejected.
- The validator is side-effect-free. It does not bring up an interface, install firewall rules, or prove that a provider endpoint is reachable.

## Required command contract

- pps privacy on PROFILE: preflight the profile and dependencies; install a PPS-owned fail-closed guard before bringing up the tunnel; verify tunnel handshake, full-tunnel routes, and egress; roll back only PPS-owned state if activation fails.
- pps privacy status: report tunnel/interface, routes, guard presence, DNS resolver, IPv4/IPv6 policy, and last verification. Never print private keys or full config contents.
- pps privacy check: perform explicit egress/DNS/IPv6 checks and a controlled fail-closed test. A simple HTTPS success is not sufficient evidence.
- pps privacy off: bring the tunnel down while the guard remains in place, then remove only the exact PPS-owned nftables table after confirming the interface is down. If cleanup cannot be proven safe, keep the guard and explain recovery.

## Non-negotiable safety rules

1. Never flush or replace the global nftables ruleset; never alter unrelated tables/chains.
2. Use a uniquely named PPS-owned nftables table and refuse to overwrite it if it exists unexpectedly.
3. Parse and validate the selected WireGuard profile before changing the system; reject arbitrary PreUp/PostUp/PreDown/PostDown hooks in the first implementation.
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
- privacy off restores connectivity and leaves unrelated firewall tables unchanged;
- reboot and VirtualBox NAT reconnect behavior;
- Burp Suite/browser and representative TCP/UDP network tools behave as expected.

Do not release the feature as production-ready until these tests pass on a real Kali VM and an independent review checks the firewall/routing logic.

## Current implementation boundary

The branch includes proxy-aware process launching, manual WireGuard profile up/down support, and a strict side-effect-free profile validator. The validator now supports IPv4-only providers only by declaring an explicit future IPv6 block policy; that policy is metadata, not an installed firewall rule. It does not yet implement the system-wide guard, full-tunnel verification, DNS/IPv6 leak prevention, or safe one-command ON/OFF session management. No provider profile or disposable Kali VM integration result is available yet. Therefore privacy on must not be advertised as available.


## Firewall compiler milestone (not yet active)

The branch now contains `pps_privacy_firewall.py`, a pure policy compiler that renders a dedicated `inet pps_guard` output chain with default-drop behavior. It allows loopback, established/related traffic, the selected WireGuard interface, the numeric VPN endpoint UDP flow, and optionally DHCPv4 renewal traffic. It rejects unsafe endpoint classes and invalid interface names. Unit tests verify that the generated rules never flush or replace the global ruleset.

This is only a ruleset generator. It does not execute `nft`, install the table, inspect existing state, determine the physical route, bring up WireGuard, or perform rollback. It must not be used as a manual firewall command. Before integration, the implementation still needs disposable-VM validation for DHCP renewal, DNS behavior, IPv4/IPv6 leak blocking, endpoint routing/mark behavior, interaction with existing nftables base chains, and restoration. The session manager must refuse an existing `inet pps_guard` table rather than overwrite it, and must apply changes atomically.


## Output-filter hardening update

The generated output guard no longer includes a broad `ct state established,related accept` exception. A generic established-flow exception can keep pre-activation direct connections alive after the guard is enabled, weakening the intended fail-closed boundary. New outbound flows must leave through the WireGuard interface, except the narrowly scoped numeric endpoint UDP flow and optional DHCPv4 lease traffic. The pure renderer also exposes a delete statement for only `inet pps_guard`; a future manager must first verify the table's exact expected structure and ownership before using it.

This remains a policy compiler and test artifact, not an installed kill switch. In particular, the WireGuard endpoint route/mark behavior, DHCP renewal, IPv6-only endpoint handling, existing nftables chains, and safe rollback have not yet been integration-tested. Do not manually apply generated rules on a working system.


## Session transaction core milestone (not a Linux backend)

The branch now includes `pps_privacy_session.py`, a backend-agnostic orchestration core. Its injected backend contract makes command ordering testable without executing host networking commands. Enable refuses a pre-existing PPS guard or an already-active interface, installs the guard before starting WireGuard, then requires handshake, route, and egress verification. Failed activation attempts to bring the interface down before removing the guard; if down-state cannot be proven, it reports guarded recovery. Disable likewise keeps the guard until the interface is confirmed down.

This module deliberately has no concrete backend, subprocess calls, root escalation, persistent session state, or CLI integration. A mock backend passing unit tests is not evidence that nftables/WireGuard behavior is safe on Kali. Before a real backend is written, the policy itself still requires independent review and disposable-VM tests for DHCP, endpoint routing, DNS, IPv6, pre-existing firewall chains, and rollback. In particular, a backend must verify exact table ownership/structure before cleanup; it must not infer ownership from the table name alone.


## Ownership-proof hardening milestone

The session backend contract now separates `guard_exists()` from `guard_is_owned_and_expected()`. A matching table name alone is never sufficient proof of ownership: the future backend must inspect the complete table and compare it with the exact PPS-generated structure before cleanup. Disable refuses to remove a foreign or modified table. Activation verifies ownership after installation, and rollback after a partial install removes a guard only when the interface is proven down and exact ownership is confirmed. If ownership is uncertain, the state remains guarded-recovery and no destructive cleanup is attempted.

This is still a mock-tested transaction contract, not an nftables inspector or Linux backend. The backend must implement ownership comparison defensively (including unexpected extra chains/rules and malformed nft output) and must not interpret command failure or incomplete output as proof of ownership. No live firewall or route changes have been made.


## nftables ownership verifier milestone (read-only)

A new pure verifier consumes the JSON representation of `nft -j list table inet pps_guard` and accepts ownership only when exactly one expected table, one output base chain, and the exact policy-derived rule sequence are present. It ignores kernel-assigned handles but rejects extra chains/rules/objects, changed chain policy, mismatched rules, malformed JSON, and incomplete output. The verifier does not run `nft`; it is not yet connected to the session backend.

Important compatibility gate: nft JSON expression encoding can vary by nftables release and rule construction. The current expected schema is intentionally strict and unit tests use representative fixtures, not output captured from the target Kali release. Before using this verifier against a host, capture real output in a disposable VM, compare it with fixtures, and add version-specific compatibility tests. Any unknown shape must remain “ownership unproven”; never loosen the check to accept partial matches.


## Read-only nftables inspection boundary milestone

`pps_nft_inspect.py` adds a narrowly scoped inspector for `nft -j list table inet pps_guard`. It uses an argument array with `shell=False`, no stdin, a bounded timeout, UTF-8 decoding, and a 256 KiB output limit. It never requests root and never applies rules. Results distinguish exact ownership, a retrieved-but-nonmatching table, and unknown state. In particular, non-zero exit, missing executable, timeout, or malformed command execution is never treated as proof that the table is absent.

This inspector is not connected to session activation/deactivation. Its parser is still validated against synthetic fixtures only; it must be checked against actual nft JSON captured from the target Kali/nftables version in a disposable VM before it can authorize cleanup. No firewall changes have been made.
