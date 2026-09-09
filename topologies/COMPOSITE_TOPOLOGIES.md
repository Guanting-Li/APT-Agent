# Composite-Method Showcase Topologies

Three topologies designed to exercise and demonstrate HARMer's **composite
attack-planning metric** — *probability of attack success on a path*:

```
P = max over attack paths of  ∏ p_h ,   where  p_h = cvss / 10
```

(See HARMer / Enoch et al., Eq. 3–4. The composite planner selects the attack
path that **maximises the product** of per-host exploitation probabilities.)

Each topology isolates a *different* facet of composite behaviour, so that the
composite planner's choice provably differs from the shortest-path metric (and,
in one case, from a naive "pick the most-reliable hops" heuristic).

All files use the project's standard topology schema: `hosts[]` (id, role),
`edges[]` (src, dst, port, service, cvss, optional impact, exploit,
pivot_network, version), and a single `goal`. Every edge's `cvss` doubles as the
success probability of that hop (`p_h = cvss/10`), so tuning an edge tunes the
demonstration.

---

## How to use

Enumerate every attacker→goal path and see what each metric selects:

```bash
python3 topologies/verify_composite.py topologies/topo_composite_*.json
```

The verifier prints, per topology, all paths with their length and
`P = ∏ p_h`, then reports the choice of:
- **shortest-path** (`SP = min |AP|`, hop count),
- **composite** (`P = max ∏ p_h`),
- **(reference) max-min-p** — the naive "most-reliable-hops" heuristic, shown
  only to highlight where it disagrees with composite.

**Validation rule:** if your composite planner selects the path marked
**WINNER** in each table below, it is behaving correctly. Change any `cvss` and
re-run the verifier to re-derive the expected winner.

---

## 1. `topo_composite_reliable_detour.json` — length-for-reliability trade-off

**Feature shown:** composite will take a **longer** path when it is more
reliable, diverging from the shortest-path metric.

**Structure:** 6 hosts, 10 edges, 6 distinct attacker→goal paths. Two public
entries (ftp, http); a tempting short 2-hop SSH-brute shortcut to the goal; a
medium 3-hop route through a relay; and a long 4-hop route through reliable
backdoors (ftp → irc → samba → ftp).

| Metric | Path | Length | P |
|---|---|---|---|
| shortest-path | `attacker → .40 → goal` | 2 | 0.27 |
| **composite (WINNER)** | `attacker → ftp → irc → samba → goal` | **4** | **0.87** |

**Takeaway:** composite chooses a path **2× longer** because it is **~3× more
reliable**. Clear divergence from shortest-path.

---

## 2. `topo_composite_trellis.json` — multiplicative compounding / poison-hop

**Feature shown:** composite as a real optimisation over many **equal-length**
paths, where the hop-count metric is *ambiguous*; and the multiplicative
"poison-hop" penalty.

**Structure:** a 3-layer lattice. Each layer has a *reliable* and an
*unreliable* host, fully cross-connected to the next layer (8 hosts incl. goal,
14 edges). **All 8 attacker→goal paths have length 4**, so the shortest-path
metric cannot choose between them.

| Metric | Path | Length | P |
|---|---|---|---|
| shortest-path | AMBIGUOUS — 8 paths tie at length 4 | 4 | — |
| **composite (WINNER)** | `attacker → L1a → L2a → L3a → goal` (all-reliable) | 4 | **0.858** |
| worst path (all-unreliable) | `attacker → L1b → L2b → L3b → goal` | 4 | 0.157 |

**Takeaway:** a single unreliable hop multiplicatively collapses the product
(0.858 → as low as 0.157). Composite uniquely finds the all-reliable thread;
shortest-path is blind here.

---

## 3. `topo_composite_goldilocks.json` — product ≠ length and ≠ per-hop reliability

**Feature shown:** composite maximises the **product**, which is neither
"shortest" nor "most reliable per hop". This is the subtle, strongest
demonstration.

**Structure:** 9 hosts, three routes to one goal:
- **X** — short + risky: 2 hops, p = 0.55/hop.
- **Z** — medium: 3 hops, p = 0.93/hop.
- **Y** — long: 6 hops, p = **0.95**/hop (every hop *more* reliable than Z's).

| Metric | Route | Length | P |
|---|---|---|---|
| shortest-path | X | 2 | 0.30 |
| naive "most-reliable-hops" (max-min p) | Y | 6 | 0.735 |
| **composite (WINNER)** | **Z** | **3** | **0.804** |

**Takeaway:** Y's individual hops are each more reliable than Z's, yet composite
**rejects** Y because length compounds the decay (`0.95⁶ = 0.735 < 0.93³ =
0.804`). Three metrics → three different paths. Proves composite optimises the
product, not length and not per-hop reliability.

---

## Design notes & tuning

- **`p_h = cvss/10`.** To make a hop *reliable*, give it a high-CVSS, near-
  deterministic exploit (vsftpd/unrealircd/samba backdoors ≈ 9.3–9.8 → p ≈
  0.93–0.98). To make a hop *unreliable*, use a brute-force/credentialed module
  (ssh_login / telnet_login / postgres) with a deliberately low cvss (3.0–6.0).
- **Make composite favour length** (T1): one short path must contain a single
  low-p hop so its product falls below a longer all-reliable path.
- **Make shortest-path ambiguous** (T2): keep all paths the same length and vary
  only per-hop reliability.
- **Defeat the per-hop heuristic** (T3): the long path's hops must each have
  *higher* p than the medium path's, but enough extra hops that the product
  still loses (`p_long^Llong < p_med^Lmed`).
- **`impact` (aim_h)** is included on internal edges so these same topologies can
  later drive the **risk-prioritisation** tie-break `Risk_ap = Σ p_h·aim_h`
  (Eq. 2) without restructuring.
- Re-run `verify_composite.py` after any edit; it is the source of truth for the
  expected winner.

## Files

| File | Facet of composite shown |
|---|---|
| `topo_composite_reliable_detour.json` | longer path wins when more reliable (vs shortest-path) |
| `topo_composite_trellis.json` | equal-length paths; compounding / poison-hop |
| `topo_composite_goldilocks.json` | product ≠ length and ≠ per-hop reliability |
| `verify_composite.py` | independent path enumerator / expected-winner oracle |
