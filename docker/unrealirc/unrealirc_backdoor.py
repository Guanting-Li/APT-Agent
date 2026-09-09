#!/usr/bin/env python3
"""
UnrealIRCd 3.2.8.1 backdoor simulator.

Reproduces the exact behaviour targeted by Metasploit's
exploit/unix/irc/unreal_ircd_3281_backdoor:
  1. Listens on port 6667, speaks enough IRC to satisfy the module.
  2. When any line starting with 'AB;' is received, the rest is executed
     as a shell command — this is how the backdoor payload (reverse shell)
     is delivered.
"""
import os
import socket
import subprocess
import threading

IRC_PORT = 6667


def _write_flags():
    """Write flag files from FLAG env var so the same image works for H2 and H3."""
    flag = os.environ.get("FLAG", "flag{unreal_ircd_backdoor_pwned}")
    for path in ("/flag.txt", "/home/msfadmin/flag.txt",
                 "/home/msfadmin/user.txt", "/root/user.txt", "/root/root.txt"):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(flag + "\n")
        except Exception:
            pass


def _handle_irc(conn):
    conn.sendall(b":irc.local 020 * :Please wait while we process your connection.\r\n")
    try:
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line_bytes, buf = buf.split(b"\n", 1)
                line = line_bytes.decode("utf-8", errors="ignore").strip()

                if line.startswith("AB;"):
                    cmd = line[3:]
                    print(f"[irc] backdoor triggered: {cmd[:80]}", flush=True)
                    subprocess.Popen(cmd, shell=True, close_fds=True)

                elif line.upper().startswith("NICK") or line.upper().startswith("USER"):
                    conn.sendall(b":irc.local 001 user :Welcome to the IRC network\r\n")

                elif line.upper().startswith("PING"):
                    token = line[5:] if len(line) > 5 else "ping"
                    conn.sendall(f":irc.local PONG :{token}\r\n".encode())

    except Exception as e:
        print(f"[irc] client error: {e}", flush=True)
    finally:
        conn.close()


def main():
    _write_flags()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", IRC_PORT))
    srv.listen(10)
    print(f"[UnrealIRCd 3.2.8.1] listening on port {IRC_PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        print(f"[irc] connection from {addr}", flush=True)
        threading.Thread(target=_handle_irc, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
