# APT-Agent

Reference implementation for **APT-Agent: Reliable Autonomous Penetration Testing
through Action, State and Topology Grounding**.

APT-Agent is a fully automated penetration-testing framework that grounds LLM
decisions at three levels: the executable action space (entity rectification
against an authoritative Metasploit-module database), the operational state
(a failure-aware Context Management Module), and the network topology
(graph-based planning with verified cross-subnet pivoting).

> ⚠️ **Authorized use only.** This is offensive-security research tooling. Run it
> exclusively against systems you own or are explicitly authorized to test, in an
> isolated lab. You are responsible for complying with all applicable laws.

## Repository layout

| Path | Description |
|------|-------------|
| `APT-Agent.py` | Per-hop execution agent (RECON → EXPLOIT → EXFILTRATE) for a single target host. Launched as a subprocess by the orchestrator. |
| `run_harmat_campaign.py` | Multi-host campaign orchestrator: HARM graph planning, per-hop invocation, and cross-subnet pivoting. |
| `harmat/` | Vendored HARM analysis library (Enoch et al.), used unmodified for graph-based path selection. MIT-licensed — see `harmat/LICENSE.txt`. |
| `topologies/` | Network-topology JSON specifications, including the five reported in the paper (linear chain, dumbbell, star, Equifax-inspired, enterprise). |
| `docker/` | Vulnerable target containers (one service each) and the isolated-network compose file used for the multi-host evaluation. |
| `db/` | Scripts to build the `art_agent` MySQL database of valid Metasploit modules (the rectification back-end). |
| `data/` | Module-name lists and credential wordlists used by rectification and brute-force-dependent services. |

## Requirements

- Linux with **Metasploit Framework** (`msfrpcd` running for RPC access)
- **MySQL** (for the module-rectification database)
- Python 3.11 or 3.12 (prebuilt `harmat` extensions are included for these; rebuild
  from the Cython sources in `harmat/` for other versions)
- Python packages: see `Pipfile` (LangChain, `mysql-connector-python`, `rapidfuzz`,
  `python-dotenv`, an LLM SDK). Note: pin versions to your environment; the LLM
  client requires an OpenAI-compatible API.

## Setup

1. **Configuration.** Copy `.env.example` to `.env` and fill in your values
   (OpenAI key, Metasploit RPC password/port, MySQL connection, lab IPs).
   `.env` is gitignored — never commit real keys.

2. **Rectification database.** Build the `art_agent` MySQL database from the
   module lists:
   ```bash
   python db/add_modules2database.py    # populates the module table(s)
   ```
   (See `db/SQL_ART_LLM.py` for the schema/query logic.)

3. **Targets.** Bring up the vulnerable containers:
   ```bash
   cd docker && docker compose up -d
   ```
   The compose file places interior hosts on `internal: true` bridges so they are
   reachable only via pivoting.

4. **Metasploit RPC.** Start the RPC daemon so the agent can drive Metasploit:
   ```bash
   msfrpcd -P <MSF_PASSWORD> -p <MSF_PORT> -n
   ```

## Running

**Single host** (per-hop agent directly):
```bash
TARGET_IP=<ip> TARGET_SERVICE=<svc> TARGET_PORT=<port> python APT-Agent.py
```

**Multi-host campaign** (orchestrator over a topology):
```bash
python run_harmat_campaign.py --topology topologies/topo_dumbbell_cvssv2.json --model gpt-4o
```

Pivoting reuses HARMer's session-based routing (Meterpreter upgrade + MSF
`route add`) as the primary mechanism, with a shell-based TCP port-forwarder as a
fallback for hosts compromised through command-shell-only exploits.

## Notes

- Some defaults in the code (lab IP addresses, a `/home/will/...` wordlist path,
  a placeholder MySQL password) reflect the original lab environment. Override
  them via `.env` / environment variables for your own setup.
- `harmat/` is redistributed under its original MIT license; all other code in
  this repository is released under the MIT license in `LICENSE`.
