# LinuxIpDiscovery

`LinuxIpDiscovery.exe` is a Windows 10/11 command-line utility for discovering likely IPv4/IPv6/MAC identity of an Ubuntu host connected by direct Ethernet cable or via unmanaged switch when the Linux IPv4 and subnet are unknown. It combines passive capture and active Layer-2 probing (ARP + IPv6 ND) to maximize discovery success. **It cannot guarantee recovery of an arbitrary silent static IPv4 outside the probed candidate ranges; this is a protocol limitation, not an implementation bug.**

## Prerequisites

- Windows 10/11
- Administrator shell
- Npcap >= 1.79 from https://npcap.com
  - During install, enable **WinPcap API-compatible Mode**
- .NET 8 SDK (build only)

## Build

```powershell
dotnet restore
dotnet test LinuxIpDiscovery.slnx -c Release
dotnet publish src/LinuxIpDiscovery/LinuxIpDiscovery.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
```

Output binary:

- `src/LinuxIpDiscovery/bin/Release/net8.0/win-x64/publish/LinuxIpDiscovery.exe`

## Usage

```powershell
LinuxIpDiscovery.exe [options]
```

### CLI flags

- `--adapter <index|name>`: select adapter without prompt
- `--all-adapters`: include virtual/tunnel adapters
- `--ranges <cidr,cidr>`: user-supplied IPv4 candidate ranges
- `--rate <pps>`: ARP packet rate limit (default `500`)
- `--full-private`: include full RFC1918 sweep (slow; warns by duration)
- `--configure-ip`: optionally add temporary secondary IPv4 for post-discovery verification
- `--json <file>`: save JSON result file
- `--verbose`: detailed packet-level output

## Example output

```text
Linux IP Discovery Tool
=======================

Available Ethernet adapters:

[1] Intel(R) Ethernet Controller
    Status: Up
    MAC: AA-BB-CC-DD-EE-FF
    Link speed: 1000 Mbps

Select adapter: 1
For best results, unplug and replug the Ethernet cable on the Linux device now — this forces gratuitous ARP and IPv6 announcements that make discovery near-certain.

Discovery completed.

MAC: 00-11-22-33-44-55
Confidence: Confirmed
  Address: 192.168.50.10
  Address: fe80::211:22ff:fe33:4455
  Evidence: Passive ARP Response
```

## Discovery model (honest summary)

- Passive: listens for ARP/IPv4/IPv6/ICMPv6/LLDP-like evidence.
- Active IPv6: probes `ff02::1` and parses replies.
- Active ARP: sends raw Ethernet broadcast ARP over prioritized candidate IPv4 space.
- Correlation: groups by MAC and outputs confidence labels (`Confirmed`, `Probable`, `Tentative`).

## Troubleshooting

### Npcap missing
Install Npcap and ensure **WinPcap API-compatible Mode** was selected. Run tool as Administrator.

### Adapter not listed
Use `--all-adapters`, disable VPN/virtual switch filters temporarily, and verify physical link is up.

### No results
- Replug cable on Linux side to force gratuitous ARP + IPv6 DAD/RS.
- Add likely ranges with `--ranges`.
- Use `--full-private` if you can tolerate runtime.
- Ensure only intended adapter is selected.

### Wi-Fi interference / multiple interfaces
Keep Wi-Fi up if needed, but explicitly select correct Ethernet adapter.

### Hyper-V virtual switch bound to NIC
Virtual switch bindings can mask expected traffic behavior. Try temporarily unbinding or selecting a dedicated NIC.

### Multiple devices on switch
Tool reports confidence labels and may show unrelated devices. Validate by repeated evidence and MAC consistency.

### Adapter promiscuous limitations
Some drivers restrict capture/injection features; try another NIC/driver version.

## Docs

- `docs/01-feasibility.md`
- `docs/02-architecture.md`
- `docs/04-testing.md`
- `docs/05-limitations.md`
