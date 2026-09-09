FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends perl ncat nmap && rm -rf /var/lib/apt/lists/*

# Symlink ncat as nc so Metasploit's reverse_netcat payload works
RUN ln -sf /usr/bin/ncat /usr/bin/nc

RUN useradd -m -s /bin/sh msfadmin

RUN echo "flag{unreal_ircd_backdoor_pwned}" > /flag.txt && \
    mkdir -p /home/msfadmin /root && \
    echo "flag{unreal_ircd_backdoor_pwned}" > /home/msfadmin/flag.txt && \
    cp /flag.txt /home/msfadmin/user.txt && \
    cp /flag.txt /root/user.txt && \
    cp /flag.txt /root/root.txt && \
    chown msfadmin:msfadmin /home/msfadmin/flag.txt /home/msfadmin/user.txt

COPY unrealirc_backdoor.py /unrealirc_backdoor.py

EXPOSE 6667

CMD ["python3", "-u", "/unrealirc_backdoor.py"]
