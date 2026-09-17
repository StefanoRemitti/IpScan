# Phase 1 — Feasibility analysis

## Fundamental conclusion

A host on the same Layer-2 broadcast domain is reachable at Ethernet regardless of IPv4 subnet alignment, but its IPv4 address is only learned if it emits a frame containing that address or answers a probe that causes it to reveal one.

For Ubuntu/Linux defaults, the key behavior is ARP weak-host response semantics (`arp_ignore=0`): Linux commonly answers ARP requests for any local IPv4 address on the receiving interface, even when the requester is outside the target subnet, and replies from the receiving interface MAC. This enables Layer-2 ARP broadcast probing without assigning Windows an in-subnet IPv4, **if the tool sends raw Ethernet ARP frames directly** (Windows IP stack APIs alone are insufficient because they enforce local-subnet routing rules).

## Critical solvability answer (§4)

**No** — discovery of a fully silent Linux host with arbitrary static IPv4 is not guaranteed by any passive method or bounded active method when address+subnet are unknown. If the true IPv4 lies outside the probed candidate set, the problem is an unbounded search over `2^32` IPv4 addresses.

## Active ARP viability and bounded search cost

Full space ARP sweep (`2^32`) is infeasible. Practical discovery therefore uses prioritized bounded ranges:

- RFC1918 high-probability /24s and common host offsets (`.1`, `.2`, `.10`, `.20`, `.100`, `.200`, `.254`)
- Link-local `169.254.0.0/16`
- Common lab/site ranges
- User-supplied CIDRs (`--ranges`)

Example cost: scanning `10.0.0.0/16` (~65,536 targets) at 500 pps takes ~131 seconds (plus receive/processing overhead).

## Deterministic and near-certain techniques in practice

1. **IPv6 link-local discovery is deterministic when IPv6 is enabled:** send ICMPv6 Echo/NS to `ff02::1` from adapter `fe80::` source. Linux typically replies from `fe80::...`, exposing MAC+interface identity. Ubuntu generally enables IPv6 by default even when IPv4 is static.
2. **ICMPv6 Node Information Query (RFC 4620):** attempted optionally, but Linux generally does not implement NI replies by default; failure is expected.
3. **Passive capture is high-yield after link bounce:** collect gratuitous ARP/probes/requests, IPv6 DAD and RS/NS/NA, multicast control traffic (mDNS/LLMNR/SSDP/DHCPv6/MLD/IGMP), and L2 control protocols (LLDP/CDP/STP). Prompt user to unplug/replug Linux cable to force startup announcements.
4. **MLD/DAD leakage:** solicited-node multicast (`ff02::1:ffXX:XXXX`) leaks lower 24 bits of IPv6 interface identifier.

## Topology behavior: direct cable vs unmanaged switch

Promiscuous mode does **not** reveal arbitrary third-party unicast across a learning switch. Visible traffic is:

- broadcast
- multicast
- unknown-unicast flooding
- traffic to/from local port

Therefore passive discovery through a switch sees mainly broadcast/multicast (still enough for ARP/ND techniques). With direct cable, all traffic between endpoints is visible.

Active ARP sweeping works the same in both topologies:

- ARP requests are Ethernet broadcast and flooded by switch
- ARP replies are unicast back to scanner MAC, so scanner receives them

## Conditions that break ARP-based discovery

ARP sweep can fail when Linux/network policy blocks responses, including:

- `arp_ignore` hardened values
- `arp_filter` policy routing interactions
- strict `rp_filter` side effects in asymmetric paths
- host firewall/netfilter/eBPF dropping ARP/ICMPv6 responses

## Two-NIC Linux host implications

Linux replies from the receiving interface MAC. Under default weak-host ARP behavior, a connected interface may answer for an IP assigned on another interface. Consequences:

- discovery can reveal multiple IPs through one connected port
- network-only methods cannot reliably map discovered IP to physical Linux port
- report answering MAC as fact; infer port attribution only as tentative heuristic

If different discovered IPs respond from different source MACs, they are likely different interfaces/devices, but this remains heuristic.

## What makes discovery deterministic

Deterministic outcomes require at least one of:

- console/serial access
- forced link-up event (unplug/replug) causing announcements
- cooperating Linux-side agent/service
- DHCP-enabled Linux configuration

Without one of these, guaranteed arbitrary static IPv4 discovery is impossible.
