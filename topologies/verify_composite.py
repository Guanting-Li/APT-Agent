#!/usr/bin/env python3
"""
Independently enumerate every attacker->goal path in a topology JSON and report
what each HARMer planning metric would select, so the composite-method
topologies can be validated against expected output.

Metrics (per the HARMer paper):
  * shortest-path : min number of hops      (SP = min |AP|)
  * composite     : max product of p_h      (P  = max prod, p_h = cvss/10)
  * (reference) max-min-p : the naive 'most-reliable-hops' heuristic, shown only
    to highlight where it disagrees with composite.

Usage:  python3 topologies/verify_composite.py topologies/topo_composite_*.json
"""
import json
import sys
from itertools import count


def load(path):
    with open(path) as f:
        topo = json.load(f)
    adj = {}
    for e in topo["edges"]:
        adj.setdefault(e["src"], []).append((e["dst"], e["cvss"] / 10.0))
    return adj, topo["goal"]


def all_paths(adj, start, goal):
    """All simple paths start->goal as list of (nodes, edge_probs)."""
    out = []
    def dfs(node, nodes, probs):
        if node == goal:
            out.append((nodes[:], probs[:]))
            return
        for dst, p in adj.get(node, []):
            if dst not in nodes:
                dfs(dst, nodes + [dst], probs + [p])
    dfs(start, [start], [])
    return out


def report(path):
    adj, goal = load(path)
    paths = all_paths(adj, "attacker", goal)
    if not paths:
        print(f"{path}: NO attacker->goal path found"); return
    rows = []
    for nodes, probs in paths:
        prod = 1.0
        for p in probs:
            prod *= p
        rows.append((len(probs), prod, min(probs), nodes))
    print("=" * 100)
    print(f"{path}   ({len(rows)} attacker->goal paths)")
    print("-" * 100)
    print(f"{'len':>3} {'P=prod p_h':>11} {'min p_h':>8}   path")
    for ln, prod, mn, nodes in sorted(rows, key=lambda r: -r[1]):
        print(f"{ln:>3} {prod:>11.4f} {mn:>8.2f}   {' -> '.join(nodes)}")
    min_len = min(r[0] for r in rows)
    sp_ties = [r for r in rows if r[0] == min_len]
    sp = min(rows, key=lambda r: (r[0], -r[1]))
    comp = max(rows, key=lambda r: r[1])
    maxmin = max(rows, key=lambda r: r[2])
    print("-" * 100)
    if len(sp_ties) > 1:
        print(f"  shortest-path picks : len {min_len} -- AMBIGUOUS, {len(sp_ties)} paths tie "
              f"(hop-count cannot choose; would pick arbitrarily)")
    else:
        print(f"  shortest-path picks : len {sp[0]}, P={sp[1]:.4f}   {' -> '.join(sp[3])}")
    print(f"  COMPOSITE   picks   : len {comp[0]}, P={comp[1]:.4f}   {' -> '.join(comp[3])}")
    print(f"  (naive max-min-p)   : len {maxmin[0]}, P={maxmin[1]:.4f}   {' -> '.join(maxmin[3])}")
    agree = "SAME path" if sp[3] == comp[3] else "DIFFERENT paths  <-- composite diverges"
    print(f"  shortest vs composite: {agree}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        report(p)
