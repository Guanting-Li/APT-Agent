FROM debian:bookworm-slim

# Real telnet server (busybox telnetd) with weak credentials.
# Metasploit's auxiliary/scanner/telnet/telnet_login authenticates against
# the standard login: / Password: prompt and yields a genuine shell session,
# which the pivot layer can upgrade to Meterpreter.

RUN apt-get update && \
    apt-get install -y --no-install-recommends busybox-static login passwd nmap python3 && \
    rm -rf /var/lib/apt/lists/*

# Weak credentials
RUN useradd -m -s /bin/sh msfadmin && \
    echo 'msfadmin:msfadmin' | chpasswd && \
    echo 'root:root' | chpasswd

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 23

CMD ["/entrypoint.sh"]
