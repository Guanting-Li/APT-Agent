FROM python:3.11-slim

# Samba usermap_script RCE simulator (CVE-2007-2447).
# This is the realistic *Linux* Samba remote code execution vulnerability
# (as shipped on Metasploitable 2), targeted by Metasploit's
# exploit/multi/samba/usermap_script.
#
# NOTE: the topology hint "ms17_010_eternalblue" refers to a Windows-only SMB
# exploit and cannot run against a Linux Samba host; usermap_script is the
# correct Linux equivalent and is what this container emulates.
#
# The exploit injects a shell command into the SMB session-setup username
# field (prefixed with "/=" and wrapped in backticks). This simulator scans
# the raw SMB stream for that signature and executes the embedded command,
# yielding a shell session the pivot layer can upgrade to Meterpreter.

RUN apt-get update && \
    apt-get install -y --no-install-recommends perl ncat nmap && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sf /usr/bin/ncat /usr/bin/nc

RUN useradd -m -s /bin/sh msfadmin

COPY samba_backdoor.py /samba_backdoor.py

EXPOSE 139 445

CMD ["python3", "-u", "/samba_backdoor.py"]
