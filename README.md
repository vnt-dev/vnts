# vnts2

Server-side implementation for vnt-compatible networking, with support for:

- TCP over TLS
- WebSocket Secure (WSS)
- QUIC
- Optional web management UI/API
- Optional persistence with SQLite
- Optional peer-to-peer server federation

## Configuration

The server reads `config.toml` from its current working directory by default.

- If `config.toml` does not exist, the server will generate one automatically using built-in defaults.
- In Docker, the working directory is `/app/data`, so the effective config path is `/app/data/config.toml`.
- You can also pass a custom config path with `--conf /path/to/config.toml`.

The repository includes a sample file at `data/config.example.toml`.

### Configuration fields

`tcp_bind`

- TCP listener address for control traffic over TLS.
- Example: `0.0.0.0:29872`
- Remove this field to disable the TCP listener.

`quic_bind`

- QUIC listener address for control traffic.
- Example: `0.0.0.0:29872`
- Remove this field to disable QUIC.

`ws_bind`

- WSS listener address.
- Example: `0.0.0.0:29872`
- Remove this field to disable WSS.

`network`

- Default virtual network CIDR used by the server.
- Example: `10.26.0.0/24`

`custom_nets`

- Additional named virtual networks.
- TOML table format:

```toml
[custom_nets]
office = "10.27.0.0/24"
lab = "10.28.0.0/24"
```

`white_list`

- List of allowed network codes.
- Empty list means no whitelist restriction.

`lease_duration`

- Device IP lease duration in seconds.
- Example: `86400` for 24 hours.

`web_bind`

- Bind address for the web management UI and HTTP API.
- Example: `0.0.0.0:29871`
- Remove this field to disable the web UI/API.

`username`

- Username for the web management login.

`password`

- Password for the web management login.

`persistence`

- Enables persistence in SQLite.
- When enabled, the server stores networks, devices, and peer-server records in `network_control.db`.

`cert`

- Path to a PEM certificate file.
- If both `cert` and `key` are omitted, the server will generate `cert.pem` automatically.

`key`

- Path to a PEM private key file.
- If both `cert` and `key` are omitted, the server will generate `key.pem` automatically.

`server_quic_bind`

- Optional QUIC bind address for server-to-server federation.
- Example: `0.0.0.0:29873`

`peer_servers`

- List of upstream or sibling server addresses for federation.
- Example:

```toml
peer_servers = ["server1.example.com:29873", "192.168.1.10:29873"]
```

`server_token`

- Shared token used for inter-server authentication.
- Set this when `server_quic_bind` or `peer_servers` is enabled.

### Runtime-generated files

The server writes several files relative to its working directory:

- `config.toml`
- `network_control.db`
- `cert.pem`
- `key.pem`
- `logs/`
- `logs/log4rs.yaml`

If you use Docker, all of these should be stored in a mounted directory so they survive container recreation.

### Notes

- If `tcp_bind` and `ws_bind` use the same address, the server will multiplex TLS TCP and WSS on that single port.
- If `persistence = false`, runtime state is not stored in SQLite.
- Certificate paths may be absolute or relative. Relative paths are resolved from the process working directory.

## Docker Deployment

The repository already includes:

- `Dockerfile`
- `docker-compose.yml`
- `rust-toolchain.toml`

### Why the Rust version is pinned

This project uses Rust 2024 edition syntax. To avoid syntax and toolchain mismatches across environments, the build is pinned to Rust `1.93.1` in both:

- `rust-toolchain.toml`
- Docker build arg `RUST_VERSION`

This is newer than the minimum required stable version and avoids edition-related compatibility problems.

### Persisted data layout

In Docker, the container runs with:

- working directory: `/app/data`

The compose file mounts:

- host `./data`
- to container `/app/data`

That means the following files will persist on the host:

- `./data/config.toml`
- `./data/network_control.db`
- `./data/cert.pem`
- `./data/key.pem`
- `./data/logs/...`

### Quick start with Docker Compose

1. Copy the sample config:

```bash
cp data/config.example.toml data/config.toml
```

2. Edit `data/config.toml` as needed.

3. Build and start the service:

```bash
docker compose up -d --build
```

4. Check logs:

```bash
docker compose logs -f
```

5. Stop the service:

```bash
docker compose down
```

### Default exposed ports

- `29871/tcp`: web UI / HTTP API
- `29872/tcp`: TLS TCP control traffic
- `29872/udp`: QUIC control traffic
- `29873/udp`: optional peer-server QUIC federation

If you do not use the web UI or peer federation, you may remove the corresponding published ports in `docker-compose.yml`.

### Deploy from scratch

If you want the server to generate its own default config and certificates:

1. Create the data directory:

```bash
mkdir -p data
```

2. Start the container:

```bash
docker compose up -d --build
```

3. After the first start, inspect the generated files in `./data`.

This is convenient for initial setup, but for controlled deployments it is better to create `data/config.toml` explicitly from `data/config.example.toml`.

### Updating the deployment

When the source code changes:

```bash
docker compose up -d --build
```

Because all persistent state is stored in `./data`, recreating the container does not remove the database, config, certificates, or logs.

### Standalone Docker commands

Build:

```bash
docker build -t vnts2:local .
```

Run:

```bash
docker run -d \
  --name vnts2 \
  -p 29871:29871/tcp \
  -p 29872:29872/tcp \
  -p 29872:29872/udp \
  -p 29873:29873/udp \
  -v "$(pwd)/data:/app/data" \
  --restart unless-stopped \
  vnts2:local
```

### Troubleshooting

If the container starts but no service is reachable:

- Check whether the listener is enabled in `config.toml`.
- Check whether the port mapping matches the bind addresses in the config.
- Check `docker compose logs -f`.

If the database is not persistent:

- Confirm `persistence = true`.
- Confirm `./data` is mounted to `/app/data`.
- Confirm the server is actually using the expected working directory.

If TLS files are missing:

- The server only auto-generates `cert.pem` and `key.pem` when custom `cert` and `key` are not provided.
- Generated files are written into the working directory, which is `/app/data` in Docker.
