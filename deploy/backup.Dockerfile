FROM postgres:17-alpine

RUN apk add --no-cache bash coreutils tar gzip python3
COPY scripts/backup.sh scripts/verify-backup.sh scripts/restore-backup.sh scripts/run-postgres.py /opt/northstar/

ENTRYPOINT ["bash", "/opt/northstar/backup.sh"]
