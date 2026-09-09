# Target Environment Setup

The multi-host evaluation runs against a set of intentionally vulnerable
services arranged into isolated network tiers. We do **not** ship prebuilt
target containers; instead this document specifies the services, versions,
exploit vectors, and network layout so you can reproduce the environment with
your own containers or VMs (e.g. Metasploitable 2 services, or minimal
emulations of each CVE).

> ⚠️ These are deliberately vulnerable services. Build and run them only on an
> isolated lab network, never on a host reachable from the public Internet.

## Network tiers

Each topology places hosts on Docker bridge networks (or equivalent VLANs).
The DMZ is reachable from the attacker; every other tier is isolated
(`internal: true`) and reachable only by pivoting through a compromised host
on the adjacent tier.

| Tier      | Subnet          | Reachable from attacker? |
|-----------|-----------------|--------------------------|
| DMZ       | `172.20.0.0/24` | yes (direct)             |
| Internal  | `172.21.0.0/24` | no — pivot via a DMZ host |
| DB tier   | `172.23.0.0/24` | no — pivot via an internal host |
| Deep      | `172.22.0.0/24` | no — 2-level pivot (used by deeper chains) |

Per-host IP addresses, roles, reachability edges, and the `pivot_network` each
internal edge requires are defined in the topology JSON files under
`topologies/`. Those JSONs are the authoritative specification — build one host
per node, on the subnet implied by its IP.

## Services and exploit vectors

| Service    | Version                          | Port      | Metasploit module                          |
|------------|----------------------------------|-----------|--------------------------------------------|
| FTP        | vsftpd 2.3.4                     | 21        | `exploit/unix/ftp/vsftpd_234_backdoor`     |
| HTTP       | Apache 2.2.8 / PHP 5.2.4 (CGI)   | 80        | `exploit/multi/http/php_cgi_arg_injection` |
| IRC        | UnrealIRCd 3.2.8.1               | 6667      | `exploit/unix/irc/unreal_ircd_3281_backdoor` |
| SMB        | Samba 3.0.20                    | 139 / 445 | `exploit/multi/samba/usermap_script`       |
| SSH        | OpenSSH, weak credentials        | 22        | `auxiliary/scanner/ssh/ssh_login`          |
| Telnet     | weak credentials                 | 23        | `auxiliary/scanner/telnet/telnet_login`    |
| PostgreSQL | weak credentials                 | 5432      | `exploit/linux/postgres/postgres_payload`  |

These are the canonical Metasploitable 2 vulnerabilities. You can satisfy the
setup with the real Metasploitable 2 services, or with lightweight per-service
containers that emulate each backdoor/credential weakness and expose the port
above.

## Flags

Place a `flag.txt` on each host (the exfiltration objective). Interior/goal
hosts hold the campaign flag; the orchestrator advances only after the current
host is compromised and the route to the next subnet is established. A common
convention is `/flag.txt` plus copies under the service account's home
directory (e.g. `/home/msfadmin/flag.txt`).

## Bringing it up

1. Create the four bridge networks above (mark the non-DMZ ones internal).
2. Launch one container/VM per host defined in the chosen topology JSON,
   attaching it to the subnet(s) implied by its IP and exposing the service
   port for its role.
3. Ensure the attacker host can reach the DMZ subnet only.
