#!/usr/bin/env python3
"""
vsftpd 2.3.4 backdoor simulator.

Reproduces the exact behaviour targeted by Metasploit's
exploit/unix/ftp/vsftpd_234_backdoor:
  1. Listens on port 21, speaks minimal FTP.
  2. When a USER command contains ':)', starts a raw shell listener on port 6200.
  3. Metasploit connects to port 6200 and gets an interactive /bin/sh.
"""
import os
import socket
import subprocess
import threading

FTP_PORT     = 21
BACKDOOR_PORT = 6200


def _serve_backdoor():
    """Open port 6200 and hand the first accepted connection a raw shell."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", BACKDOOR_PORT))
    srv.listen(1)
    print(f"[backdoor] listening on port {BACKDOOR_PORT}", flush=True)
    conn, addr = srv.accept()
    print(f"[backdoor] connection from {addr}", flush=True)
    srv.close()

    # Use subprocess so fd wiring is handled reliably inside Docker.
    proc = subprocess.Popen(
        ["/bin/sh"],
        stdin=conn,
        stdout=conn,
        stderr=conn,
        close_fds=True,
    )
    proc.wait()
    conn.close()


def _handle_ftp(conn):
    conn.sendall(b"220 (vsFTPd 2.3.4)\r\n")
    backdoor_triggered = False
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            line = data.decode("utf-8", errors="ignore").strip()
            cmd  = line.upper()

            if cmd.startswith("USER"):
                username = line[5:].strip() if len(line) > 5 else ""
                if ":)" in username and not backdoor_triggered:
                    # Start backdoor listener before replying so Metasploit
                    # can connect immediately after receiving the 331.
                    threading.Thread(target=_serve_backdoor, daemon=True).start()
                    backdoor_triggered = True
                conn.sendall(b"331 Please specify the password.\r\n")

            elif cmd.startswith("PASS"):
                conn.sendall(b"230 Login successful.\r\n")

            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye.\r\n")
                break

            else:
                conn.sendall(b"500 Unknown command.\r\n")

    except Exception as e:
        print(f"[ftp] client error: {e}", flush=True)
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", FTP_PORT))
    srv.listen(10)
    print(f"[vsftpd 2.3.4] listening on port {FTP_PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        print(f"[ftp] connection from {addr}", flush=True)
        threading.Thread(target=_handle_ftp, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
