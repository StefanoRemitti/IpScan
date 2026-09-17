# Phase 2 — Architecture

Technology choice: **C# / .NET 8**. Publish as self-contained single-file `win-x64` executable.

- Capture/injection: **SharpPcap + PacketDotNet** over Npcap (mature, stable parser stack, avoids extensive custom `wpcap.dll` P/Invoke)
- Adapter/IP integration: `System.Net.NetworkInformation` + selective Windows command/API interaction for temporary config

Why not C/C++: no material benefit because Npcap dependency remains; C# gives faster maintainable delivery and safer packet/model code.
Why not Python: deployment friction on technician PCs (runtime/packaging/admin policy).

## Components

| Component | What it does | Why needed | API/library | Privileges | Limitations |
|---|---|---|---|---|---|
| Adapter enumeration | Lists usable NICs, status, MAC, speed | Technician must choose correct cable-facing adapter | `GetAllNetworkInterfaces`, SharpPcap device list | User/admin | Virtual adapters can confuse mapping |
| Npcap capture | Packet receive in promiscuous mode | Passive discovery and response parsing | SharpPcap/Npcap | Admin in common installs | Switch hides third-party unicast |
| Npcap raw transmit | Sends Ethernet ARP/IPv6 probes | Active L2 discovery independent of Windows IPv4 subnet | SharpPcap `SendPacket` | Admin | Driver/NIC capability dependent |
| ARP engine | Builds/parses ARP request/reply/probe/gratuitous | Primary IPv4 discovery lever | Core protocol library | none beyond capture rights | Fails if Linux/network suppresses ARP replies |
| IPv6 ND engine | Builds ICMPv6 echo/NS, parses ND options | Deterministic link-local discovery when IPv6 enabled | Core protocol + PacketDotNet | capture/send rights | NI query often unsupported on Linux |
| Passive sniffer/classifier | Classifies ARP, ND, L3/L4 control traffic, LLDP/CDP/STP | Highest-yield near-deterministic when link bounces | PacketDotNet + custom classifiers | capture rights | Noise/false positives in shared switch domains |
| Candidate IPv4 generator | Produces prioritized bounded ranges + user CIDRs | Makes ARP search practical | Core candidates module | none | Cannot guarantee arbitrary unknown IPv4 |
| Device correlation/scoring | Groups evidence by MAC, labels confidence | Prevent reporting unrelated traffic as target | Core correlation module | none | Port attribution remains heuristic |
| Optional Windows reconfiguration | Adds temporary secondary IPv4/route for verification | Allows post-discovery reachability tests | Windows netsh/IP Helper equivalent behavior | Admin | Must be restored reliably |
| Result aggregation | Consolidates addresses/method/confidence | Human + machine readable output | Core + JSON serializer | none | Confidence is probabilistic except direct repeats |
| CLI | Inputs, prompts, progress, safety messaging | Technician workflow | .NET console app | none | Operator errors still possible |
| Cleanup/restore | Ctrl-C/unhandled/process-exit cleanup | Prevent persistent local network misconfiguration | process hooks | none | Hard kill can still bypass cleanup |
