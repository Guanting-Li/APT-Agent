FROM python:3.11-slim

# Apache mod_cgi RCE simulator (Shellshock-style, CVE-2014-6271).
# Reproduces the behaviour targeted by Metasploit's
# exploit/multi/http/apache_mod_cgi_bash_env_exec:
#   - serves a CGI endpoint at /cgi-bin/status
#   - a crafted User-Agent header of the form "() { :; }; <cmd>" is executed
#     server-side, yielding a shell — matching the Shellshock injection vector.

RUN apt-get update && \
    apt-get install -y --no-install-recommends perl ncat nmap && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sf /usr/bin/ncat /usr/bin/nc

RUN useradd -m -s /bin/sh msfadmin

COPY http_modcgi_backdoor.py /http_modcgi_backdoor.py

EXPOSE 80

CMD ["python3", "-u", "/http_modcgi_backdoor.py"]
