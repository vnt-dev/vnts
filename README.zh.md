# vnts2

vnt 兼容服务端，支持以下能力：

- TCP over TLS
- WebSocket Secure (WSS)
- QUIC
- 可选 Web 管理界面与 HTTP API
- 可选 SQLite 持久化
- 可选服务端互联

## 配置说明

程序默认会从当前工作目录读取 `config.toml`。

- 如果 `config.toml` 不存在，程序会按内置默认值自动生成。
- 在 Docker 中，工作目录是 `/app/data`，所以默认配置文件路径是 `/app/data/config.toml`。
- 也可以通过 `--conf /path/to/config.toml` 指定自定义配置文件路径。

仓库中已提供示例配置文件：`data/config.example.toml`。

### 配置项说明

`tcp_bind`

- TCP 控制通道监听地址，使用 TLS。
- 示例：`0.0.0.0:29872`
- 删除该字段即可关闭 TCP 监听。

`quic_bind`

- QUIC 控制通道监听地址。
- 示例：`0.0.0.0:29872`
- 删除该字段即可关闭 QUIC。

`ws_bind`

- WSS 监听地址。
- 示例：`0.0.0.0:29872`
- 删除该字段即可关闭 WSS。

`network`

- 默认虚拟网段 CIDR。
- 示例：`10.26.0.0/24`

`custom_nets`

- 额外的命名虚拟网段。
- TOML 写法示例：

```toml
[custom_nets]
office = "10.27.0.0/24"
lab = "10.28.0.0/24"
```

`white_list`

- 允许使用的网络编号列表。
- 空数组表示不启用白名单限制。

`lease_duration`

- 设备 IP 租约时长，单位为秒。
- 示例：`86400`，即 24 小时。

`web_bind`

- Web 管理界面和 HTTP API 的监听地址。
- 示例：`0.0.0.0:29871`
- 删除该字段即可关闭 Web 管理功能。

`username`

- Web 管理登录用户名。

`password`

- Web 管理登录密码。

`persistence`

- 是否启用 SQLite 持久化。
- 开启后，网络、设备和互联服务端记录会保存到 `network_control.db`。

`cert`

- PEM 证书文件路径。
- 如果 `cert` 和 `key` 都不配置，程序会自动生成 `cert.pem`。

`key`

- PEM 私钥文件路径。
- 如果 `cert` 和 `key` 都不配置，程序会自动生成 `key.pem`。

`server_quic_bind`

- 可选的服务端互联 QUIC 监听地址。
- 示例：`0.0.0.0:29873`

`peer_servers`

- 需要互联的上游或同级服务端地址列表。
- 示例：

```toml
peer_servers = ["server1.example.com:29873", "192.168.1.10:29873"]
```

`server_token`

- 服务端之间鉴权用的共享令牌。
- 开启 `server_quic_bind` 或配置 `peer_servers` 时建议同时设置。

### 运行时生成文件

程序会在当前工作目录下写入以下文件：

- `config.toml`
- `network_control.db`
- `cert.pem`
- `key.pem`
- `logs/`
- `logs/log4rs.yaml`

如果使用 Docker，建议把这些文件统一放到挂载目录中，避免容器重建后丢失。

### 额外说明

- 如果 `tcp_bind` 和 `ws_bind` 配置为同一个地址，程序会在同一端口上复用 TLS TCP 和 WSS。
- 如果 `persistence = false`，运行状态不会写入 SQLite。
- `cert` 和 `key` 支持绝对路径与相对路径。相对路径基于进程工作目录解析。

## Docker 部署说明

仓库中已包含以下文件：

- `Dockerfile`
- `docker-compose.yml`
- `rust-toolchain.toml`

### 为什么固定 Rust 版本

当前项目使用 Rust 2024 edition 语法。为了避免不同环境的 toolchain 版本差异导致语法或构建不兼容，仓库中已把构建版本固定为 `1.93.1`，位置如下：

- `rust-toolchain.toml`
- `docker-compose.yml` 中的 `RUST_VERSION`

这个版本高于项目实际最低要求，主要目的是避免 2024 edition 和相关语法特性带来的兼容问题。

### 持久化目录布局

Docker 中容器运行时的工作目录为：

- `/app/data`

`docker-compose.yml` 中已经把宿主机目录挂载到容器内：

- 宿主机：`./data`
- 容器内：`/app/data`

因此下面这些文件会直接持久化到宿主机：

- `./data/config.toml`
- `./data/network_control.db`
- `./data/cert.pem`
- `./data/key.pem`
- `./data/logs/...`

### 使用 Docker Compose 快速部署

1. 复制示例配置：

```bash
cp data/config.example.toml data/config.toml
```

2. 按需修改 `data/config.toml`。

3. 构建并启动服务：

```bash
docker compose up -d --build
```

4. 查看日志：

```bash
docker compose logs -f
```

5. 停止服务：

```bash
docker compose down
```

### 默认暴露端口

- `29871/tcp`：Web 管理界面 / HTTP API
- `29872/tcp`：TLS TCP 控制通道
- `29872/udp`：QUIC 控制通道
- `29873/udp`：可选的服务端互联 QUIC 端口

如果不使用 Web 管理或服务端互联，可以在 `docker-compose.yml` 中删除对应端口映射。

### 从空目录启动

如果希望让程序第一次启动时自动生成默认配置和证书，可以这样做：

1. 创建数据目录：

```bash
mkdir -p data
```

2. 启动容器：

```bash
docker compose up -d --build
```

3. 首次启动完成后，检查 `./data` 下自动生成的文件。

这种方式适合初始化测试；正式部署时，建议先基于 `data/config.example.toml` 手动生成 `data/config.toml`。

### 更新部署

代码更新后，重新执行：

```bash
docker compose up -d --build
```

因为所有持久化数据都保存在 `./data`，容器重建后不会丢失数据库、配置、证书和日志。

### 单独使用 Docker 命令

构建镜像：

```bash
docker build -t vnts2:local .
```

运行容器：

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

### 排查建议

如果容器启动了但服务无法访问：

- 检查 `config.toml` 中对应监听项是否启用。
- 检查端口映射是否和配置中的监听地址一致。
- 检查 `docker compose logs -f` 输出。

如果数据库没有持久化：

- 确认 `persistence = true`。
- 确认 `./data` 已挂载到 `/app/data`。
- 确认程序实际工作目录就是预期的 `/app/data`。

如果没有生成 TLS 文件：

- 只有在未显式配置 `cert` 和 `key` 时，程序才会自动生成 `cert.pem` 和 `key.pem`。
- 自动生成的证书和私钥会写入工作目录，也就是 Docker 中的 `/app/data`。
