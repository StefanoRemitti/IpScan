# Phase 5 — Fundamental limitations

1. **Guaranteed discovery of arbitrary silent static IPv4 is impossible** without cooperation or unbounded search.
2. Passive capture cannot infer an address a host never transmits.
3. Bounded ARP sweeps can miss true IPv4 if outside candidate ranges.
4. Physical-port attribution on multi-NIC Linux is not reliably solvable by network observation alone.
5. Learning switches hide third-party unicast; promiscuous mode does not bypass switch forwarding logic.
6. Hardened Linux/network policies (`arp_ignore`, firewall, ND filtering) can defeat ARP/ND probing.
7. Optional temporary Windows reconfiguration can fail or require manual recovery if process is forcibly terminated.
8. Shared broadcast domains can produce ambiguous evidence from unrelated devices; results are confidence-scored, not absolute identity proofs.
