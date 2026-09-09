#!/usr/bin/env python3
"""
Samba usermap_script (CVE-2007-2447) RCE simulator.

Reproduces the behaviour targeted by Metasploit's
exploit/multi/samba/usermap_script:

  1. Listens on SMB ports 139 and 445.
  2. The exploit places a shell command in the SMB SessionSetupAndX username
     field, prefixed with "/=" and wrapped in backticks, e.g.
         /=`nohup sh -c '<payload>'`
  3. This simulator scans the raw SMB stream for that backtick-delimited
     command and executes it as /bin/sh, giving Metasploit a shell session
     that the pivot layer can upgrade to Meterpreter.

Flag (overridable via FLAG env var) is written to the standard paths the
agent searches.
"""
import os
import re
import socket
import subprocess
import threading

SMB_PORTS = (139, 445)

# usermap_script places the command between backticks, after a "/=" marker.
_INJECTION = re.compile(rb"/=`([^`]+)`")


def _write_flags():
    flag = os.environ.get("FLAG", "flag{samba_usermap_script_pwned}")
    for path in ("/flag.txt", "/home/msfadmin/flag.txt",
                 "/home/msfadmin/user.txt", "/root/user.txt", "/root/root.txt"):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(flag + "\n")
        except Exception:
            pass


def _execute_injection(raw_cmd):
    cmd = raw_cmd.decode("utf-8", errors="ignore").strip()
    # The payload is usually "nohup sh -c '...'"; run it as-is.
    print(f"[samba] usermap_script injection: {cmd[:100]}", flush=True)
    try:
        subprocess.Popen(cmd, shell=True, close_fds=True)
    except Exception as e:
        print(f"[samba] injection error: {e}", flush=True)


def _handle_smb(conn):
    try:
        conn.settimeout(8)
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            m = _INJECTION.search(buf)
            if m:
                _execute_injection(m.group(1))
                # Send a minimal NetBIOS session response so the client
                # doesn't error out immediately.
                conn.sendall(b"\x00\x00\x00\x00")
                break
            # Cap buffer to avoid unbounded growth on noise.
            if len(buf) > 65536:
                buf = buf[-8192:]
    except Exception as e:
        print(f"[samba] client error: {e}", flush=True)
    finally:
        conn.close()


def _listen(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(10)
    print(f"[Samba usermap sim] listening on port {port}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_handle_smb, args=(conn,), daemon=True).start()


def main():
    _write_flags()
    threads = [threading.Thread(target=_listen, args=(p,), daemon=True)
               for p in SMB_PORTS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
