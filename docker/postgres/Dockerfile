FROM postgres:16-alpine

# Real PostgreSQL 16 with a weak superuser password.
# - Metasploit auxiliary/scanner/postgres/postgres_login finds postgres:postgres
# - exploit/multi/postgres/postgres_copy_from_program_cmd_exec uses the
#   superuser account to run commands and obtain a shell session.

ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres
ENV POSTGRES_DB=postgres

# Init script: write flag into a DB table at first DB initialisation.
RUN apk add --no-cache nmap python3

COPY init-flag.sh /docker-entrypoint-initdb.d/init-flag.sh

# Root-level wrapper: writes flag files to root-owned paths before postgres
# drops privileges, then hands off to the official postgres entrypoint.
COPY write-flags.sh /write-flags.sh
RUN chmod +x /write-flags.sh

EXPOSE 5432

ENTRYPOINT ["/write-flags.sh"]
CMD ["postgres"]
