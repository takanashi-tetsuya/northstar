# Northstar monitoring

The optional Compose profile starts Prometheus 3.12.0 and Grafana 13.1.0 on
loopback-only ports. Generate `deploy/secrets/grafana_admin_password` before the
first start, then run:

```sh
docker compose --profile monitoring up -d
```

- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000` (user `admin`; password from the secret file)
- Northstar liveness: `/healthz`
- Northstar dependency readiness: `/readyz`
- Prometheus exposition: `/metrics`

`alerts.yml` contains local alerting rules but no notification receiver.
Connect Prometheus to an Alertmanager or configure an equivalent managed
receiver before production. Dashboard counters survive only in Prometheus;
Northstar's in-process counters reset on restart.
