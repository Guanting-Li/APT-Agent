FROM debian:bookworm-slim

# Real OpenSSH server with weak credentials.
# Metasploit's auxiliary/scanner/ssh/ssh_login establishes a genuine shell
# session against this host, which the pivot layer can then upgrade to
# Meterpreter via post/multi/manage/shell_to_meterpreter.

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server python3 nmap && \
    rm -rf /var/lib/apt/lists/*

# Weak credentials (matches Metasploitable's msfadmin:msfadmin and root:root)
RUN useradd -m -s /bin/bash msfadmin && \
    echo 'msfadmin:msfadmin' | chpasswd && \
    echo 'root:root' | chpasswd

# Permit root login and password authentication
RUN mkdir -p /run/sshd && \
    sed -i 's/#\?PermitRootLogin.*/PermitRootLogin yes/'        /etc/ssh/sshd_config && \
    sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
