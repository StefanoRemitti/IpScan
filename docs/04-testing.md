# Phase 4 — Testing

## Automated tests (xUnit)

The suite uses recorded byte arrays (no live capture dependency) and validates:

- ARP build/parse round-trip
- gratuitous ARP / ARP probe classification
- Ethernet header parse
- EUI-64 derive/reverse
- solicited-node multicast computation
- ICMPv6 checksum over pseudo-header
- NDP option parsing
- LLDP TLV extraction
- candidate ordering/de-dup + CIDR edge parsing (`/32`, unusual masks)
- rate limiter behavior
- confidence scoring for multi-NIC/multi-device scenarios

Run:

```powershell
dotnet test LinuxIpDiscovery.slnx -c Release
```

## Manual procedure (single Windows + single Ubuntu, optional unmanaged switch)

1. Install Npcap >= 1.79 with **WinPcap API-compatible Mode**.
2. Run elevated PowerShell.
3. Connect Windows NIC to Ubuntu directly (or via unmanaged switch).
4. On Linux, prepare interface scenarios in `/etc/network/interfaces`, for example:

```ini
auto enp1s0
iface enp1s0 inet static
  address 192.168.50.10
  netmask 255.255.255.0

auto enp2s0
iface enp2s0 inet static
  address 10.10.20.5
  netmask 255.255.255.0
```

`/32` case:

```ini
auto enp1s0
iface enp1s0 inet static
  address 192.168.77.10
  netmask 255.255.255.255
```

Unusual mask case:

```ini
auto enp1s0
iface enp1s0 inet static
  address 10.42.17.10
  netmask 255.255.248.0
```

5. Bounce Linux link (`ip link set enp1s0 down; ip link set enp1s0 up`) or physically replug cable.
6. Run tool:

```powershell
LinuxIpDiscovery.exe --rate 500 --ranges 192.168.0.0/16,10.0.0.0/24 --json results.json
```

7. Validate Linux-side packet behavior:

```bash
ip -s link show enp1s0
tcpdump -ni enp1s0 arp or icmp6
```

8. Edge-case checks:
   - two NICs connected/disconnected independently
   - multiple devices on switch (verify confidence labels)
   - no link bounce initially then bounce and compare yield
   - Wi-Fi enabled on Windows + Ethernet selected explicitly
