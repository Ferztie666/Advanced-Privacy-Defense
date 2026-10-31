# Advanced Privacy Defense

Free/open-source Linux utility for proxy-aware application launches, existing WireGuard profile management, and read-only network diagnostics.

**Status:** early release; not an anonymity guarantee or independently security-audited product.

## Features
- Version 1.2.2: native proxy adapters for Subfinder, Dalfox, and Nuclei (`pps tool-run`); Nmap is blocked in proxy-only mode by design.
- CLI and Tkinter advanced GUI.
- Tor SOCKS5/SOCKS5H and HTTP(S) proxy validation.
- HTTPS egress test with curl through the configured proxy.
- Explicit Tor Project verification (`pps tor-check`) using the configured proxy and the official check API; reports verified Tor exit or failure.
- Launch child processes with proxy environment variables after successful proxy preflight.\n- `pps tool-run subfinder|dalfox|nuclei -- ...`: inject each supported scanner's native proxy flag after HTTPS preflight; Nmap is deliberately blocked in proxy-only mode because its proxy support does not cover every scan phase.
- Manage existing /etc/wireguard/*.conf profiles using wg-quick and typed confirmation.
- Read-only indicators for routes, resolver configuration, nftables, and WireGuard.
- `pps redact-log FILE`: create a separate mode-0600 copy with common tokens, authorization/cookie headers, email addresses, and `/home/USER` paths redacted.
- Atomic configuration writes with restrictive permissions.
- No telemetry.

## Scope and limitations
**Application scope:** only processes launched by pps run receive proxy variables. Apps may ignore them or use other network paths. This is not transparent packet routing. The dedicated `tool-run` adapters pass native proxy flags to Subfinder (`-proxy`), Dalfox (`--proxy`), and Nuclei (`-proxy`). This is still not a proof that every auxiliary request or DNS lookup is proxied; validate the installed tool version and egress independently. Nmap is intentionally rejected by `tool-run` in proxy-only mode because Nmap documents that `--proxies` does not cover ping, port scanning, OS discovery, or proxy-side DNS resolution. Use a separately verified full-tunnel VPN for Nmap; PPS does not yet enforce a VPN kill switch.

**System VPN scope:** WireGuard can change system routes using an existing administrator-provided profile. This project does not supply VPN servers or silently change firewall policy.

Tor SOCKS is not a general-purpose VPN. UDP, all DNS behavior, browser WebRTC, fingerprinting, malware, account identity, and traffic correlation are not comprehensively protected. A successful `pps live-test` proves only that the test request reached its HTTPS endpoint through the configured proxy. `pps tor-check` additionally checks whether the Tor Project check API recognizes that request as coming from a Tor exit. This validates that single test request, not every application or all system traffic.

No automatic kill switch is installed and no global nftables rules are modified.

## Requirements
Linux, Python 3.10+, curl; Tkinter for GUI. Optional: Tor, WireGuard tools, nftables, iproute2.

## Install on Debian/Ubuntu/Kali
```bash
git clone https://github.com/Ferztie666/Advanced-Privacy-Defense.git
cd Advanced-Privacy-Defense
bash install.sh
export PATH="$HOME/.local/bin:$PATH"
pps status
```

The installer installs distro packages and copies the app to ~/.local/share. It does not enable Tor or alter firewall rules automatically.

Run GUI: `python3 pps.py gui`

Optional launcher:
```bash
install -Dm755 pps.py "$HOME/.local/bin/pps"
export PATH="$HOME/.local/bin:$PATH"
```

## Use
```bash
sudo systemctl enable --now tor
pps set-proxy socks5h://127.0.0.1:9050
pps live-test
pps audit
pps gui
pps run -- firefox
```

WireGuard:
```bash
ls /etc/wireguard/
pps wg up wg0
sudo wg show
pps wg down wg0
```
The CLI requires exact typed confirmation before calling sudo wg-quick. Review profiles before use; wg-quick can alter system routes.

## Tests
```bash
python3 pps.py self-test
python3 -m unittest discover -s tests -v
python3 -m py_compile pps.py
```
Tests cover proxy URL validation, rejection of embedded credentials/path traversal, config permissions, Tor-check response handling, and log-redaction behavior including refusal to overwrite existing output and rejection of symlink sources. live-test performs a real HTTPS request through the configured proxy and optionally compares direct egress IP. Network tests need a working proxy and internet.

## Security model
- No shell is used for subprocess execution.
- Commands are passed as argument arrays.
- Embedded proxy credentials are rejected.
- Config is atomically written with mode 0600.
- WireGuard profile names are allow-listed.
- Firewall rules are read only.

## License
MIT; see LICENSE.

## PPS full-tunnel privacy guard development status

The repository now contains a **read-only** nftables inventory and ownership
inspection layer for the planned system-wide WireGuard privacy session. It
uses a complete `nft -j list tables` inventory before it can report the
PPS-owned table absent; command errors, oversized/malformed output, unknown
JSON objects, and duplicate target entries remain UNKNOWN. If the table is
listed, a separate exact-policy inspection is required before it is classified
as PPS-owned. This is not yet connected to a privileged backend and does not
install or remove firewall rules or start WireGuard.

The JSON shape is covered by synthetic unit fixtures only. Before any live
integration, capture and validate the actual nftables JSON schema on the target
Kali release in a disposable VM. The full-tunnel guard is not production-ready:
route handling, endpoint reachability, DHCP/NAT behavior, DNS and IPv6 leak
blocking, rollback, and tunnel-loss fail-closed behavior still require
end-to-end VM tests and independent review. Do not enable it on a daily-use
host.


## Network-origin privacy requirement (development target)

PPS is being developed to keep supported Kali guest traffic from falling back to the ordinary uplink while privacy mode is active. The intended design is a verified WireGuard full tunnel plus a PPS-owned fail-closed firewall. Remote Internet targets should normally see the selected VPN gateway's egress IP rather than the user's ISP public IP. This does not hide account identity, application data, browser fingerprints, timing correlation, or information visible to the VPN operator.

Coverage is not yet implemented or verified: the branch still has no concrete Linux session backend or integrated system-wide privacy ON/OFF commands. DNS, IPv6, browser DoH/WebRTC, raw-socket tools, UDP, containers/network namespaces, and tunnel-loss behavior require disposable-Kali-VM packet-capture tests. Do not treat current proxy support or the read-only firewall modules as system-wide protection. See [the privacy-mode design and coverage requirements](docs/PRIVACY_MODE_DESIGN.md).
