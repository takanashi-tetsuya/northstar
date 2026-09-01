# Public trust material

Place deployment-specific CA certificates and CRLs referenced by `.env` in
this directory. Docker Compose mounts only this subdirectory read-only at the
same relative path below `/app`.

Do not place private keys here. All files except this README are ignored by
Git and must be installed with permissions readable by container UID/GID
`10001:10001`.
