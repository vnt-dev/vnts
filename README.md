# vnts

[vnt](https://github.com/vnt-dev/vnt)的服务端


## 说明

1. 支持quic、tcp(tls)和wss协议，会自动生成自签名证书，也可以手动替换
2. 无参数启动后，会输出配置文件，可以修改配置文件
3. --conf-example 参数查看配置文件示例
4. 可选启用内置 IKEv2/IPsec（UDP 500/4500），让系统原生 VPN 客户端以独立设备加入指定 VNT 网络

## IKEv2/IPsec

在配置文件加入 `[ikev2]` 和一个或多个 `[[ikev2.networks]]` 即可启用。PSK 和 EAP 用户凭据会唯一映射到一个 `network_code`；EAP 需要 SAN 与 `remote_id` 匹配的独立 RSA 或 ECDSA P-256 证书。ESP 数据面统一使用 UDP/4500 NAT-T。完整示例可通过 `--conf-example` 查看。

IKEv2 客户端从对应网络的地址池获取虚拟 IP，并可跨互联服务端通信；启用了 `white_list` 时也要包含这些网络编号。普通 VNT 节点必须显式配置 `allow_ikev2 = true` 才会看到并接受 IKEv2 流量。

客户端填写规则：服务器/Remote ID 使用 `remote_id`，PSK 模式的 Local ID 必须非空且保持稳定；EAP 模式使用 `eap_users` 中的用户名和密码，并在系统中信任签发 IKE 证书的 CA。Windows 原生客户端需把 IKE/ESP 加密算法配置为 `GCMAES256`、DH 组配置为 Group14。


## Web 管理端（前端）

前端基于 Vue 3 + Vite + Tailwind CSS，源码位于 `frontend/`，构建产物输出到 `static/`
（由 rust-embed 内嵌到服务端二进制，随二进制对外提供）。

### 开发调试

```bash
cd frontend
pnpm install
pnpm dev          # 启动 Vite dev server (http://localhost:5173)
                  # 已配置 /api 代理到 http://localhost:29871，需先运行后端
```

后端默认 Web 端口为 `29871`，如修改了配置中的 `web_bind`，可通过环境变量指定代理目标：

```bash
VITE_API_TARGET=http://localhost:自定义端口 pnpm dev
```

### 构建

```bash
cd frontend
pnpm build        # 类型检查 + 构建，产物写入 ../static/
```
