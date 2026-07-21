# Deterministic fault fixture

`compose.yaml` is the one-replica Compose fixture. It builds the stateless
`fault-fixture` container and retains Compose's service label for the Docker
adapter selector. The container exposes port 8080; Compose intentionally does
not publish a fixed host port so the 2- and 3-replica overrides remain valid.

The `compose.replicas-0.yaml`, `compose.replicas-2.yaml`, and
`compose.replicas-3.yaml` files are Compose overrides for the selector mismatch
scenarios. Each override changes only `deploy.replicas`; merge it with the base
file using the normal Docker Compose `-f` option.

The fixture supports `PUT /control/{healthy|unhealthy|slow|crash|flapping|recovery}`.
Its `/health`, `/metrics`, and `/logs` endpoints do not require any external
service. In crash mode, an unavailable health response also terminates the
fixture binary, so Docker restart and stopped-container scenarios are deterministic.
