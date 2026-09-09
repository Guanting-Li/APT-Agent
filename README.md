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
| `harmat/` | Vendored HARM analysis library (Enoch et al.), used unmodified for graph-based path selection. Cython/C++ source; build with `setup.py`. MIT-licensed — see `harmat/LICENSE.txt`. |
| `topologies/` | The five network topologies evaluated in the paper: linear chain, dumbbell, star, Equifax-inspired, and enterprise. Each JSON specifies hosts, reachability/exploit edges (service, version, CVSS, Metasploit module), the `pivot_network` for internal edges, and the goal host. |
| `modules_db_dump.sql` | MySQL dump of the `art_agent` module database used for entity rectification (the `modules` table of validated Metasploit modules). |
| `data/` | Module-name list and credential wordlists used by rectification and brute-force-dependent services. |
| `TARGETS.md` | Specification of the vulnerable target environment (services, versions, exploit vectors, network tiers) so you can reproduce it. |

## Requirements

- Linux with **Metasploit Framework** (`msfrpcd` running for RPC access)
- **MySQL** (for the module-rectification database)
- Python 3.4+ (tested on 3.11/3.12)
- To build the `harmat` extensions: **Cython**, a **C++14 compiler**, and the
  **Boost Graph Library** headers (e.g. `apt install libboost-graph-dev`)
- Python packages: LangChain, `mysql-connector-python`, `rapidfuzz`,
  `python-dotenv`, and an OpenAI-compatible LLM client. Pin versions to your
  environment (`Pipfile` is a starting point).

## Setup

1. **Build the planner.** Compile the vendored `harmat` extensions in place:
   ```bash
   pip install cython
   pip install .          # or: python setup.py build_ext --inplace
   ```

2. **Configuration.** Copy `.env.example` to `.env` and fill in your values
   (OpenAI key, Metasploit RPC password/port, MySQL connection, lab IPs).
   `.env` is gitignored — never commit real keys.

3. **Rectification database.** Create the database and import the dump
   (the dump contains the tables only, so create/select the database first):
   ```bash
   mysqladmin -u <user> -p create art_agent
   mysql -u <user> -p art_agent < modules_db_dump.sql
   ```
   This loads the `modules` table (the validated Metasploit-module catalogue)
   that `APT-Agent.py` queries at startup to rectify generated module names.
   Point `MYSQL_*` in `.env` at this database.

4. **Targets.** Build the vulnerable target environment following `TARGETS.md`
   (services, versions, and isolated network tiers). The per-host details for
   each scenario are in the corresponding `topologies/*.json`.

5. **Metasploit RPC.** Start the RPC daemon so the agent can drive Metasploit:
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
python run_harmat_campaign.py --topology topologies/topo_dumbbell.json --model gpt-4o
```

Pivoting reuses HARMer's session-based routing (Meterpreter upgrade + MSF
`route add`) as the primary mechanism, with a shell-based TCP port-forwarder as a
fallback for hosts compromised through command-shell-only exploits.

## Notes

- Some defaults in the code (lab IP addresses, a wordlist path, a placeholder
  MySQL password) reflect the original lab environment. Override them via `.env`
  / environment variables for your own setup.
- `harmat/` is redistributed under its original MIT license; all other code in
  this repository is released under the MIT license in `LICENSE`.
