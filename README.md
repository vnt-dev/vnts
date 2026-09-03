# vnts

[vnt](https://github.com/vnt-dev/vnt)的服务端


## 说明

1. 支持quic、tcp(tls)和wss协议，会自动生成自签名证书，也可以手动替换
2. 无参数启动后，会输出配置文件，可以修改配置文件
3. --conf-example 参数查看配置文件示例
4. 可选启用内置 IKEv2/IPsec（UDP 500/4500），让系统原生 VPN 客户端以独立设备加入指定 VNT 网络

## IKEv2/IPsec

推荐先在 Web 管理端的“系统设置 → IKEv2/IPsec 基础配置”设置监听、Remote ID 和证书，再到“网络详情 → IKEv2 接入”配置当前网络认证，不需要手工修改 TOML。没有 `[ikev2]` 时页面会提供默认监听值；cert/key 留空会自动建立本地 CA，并签发匹配域名或 IPv4 Remote ID 的 RSA-2048 服务器证书。也可以填写自定义证书链和私钥路径。ESP 数据面统一使用 UDP/4500 NAT-T。

IKEv2 客户端从对应网络的地址池获取虚拟 IP，并可跨互联服务端通信；启用了 `white_list` 时也要包含这些网络编号。普通 VNT 节点必须显式配置 `allow_ikev2 = true` 才会看到并接受 IKEv2 流量。

系统设置可编辑服务开关、UDP 500/4500 监听、Remote ID、公网 IP、DNS 和证书路径；网络详情管理当前网络的 PSK/EAP 用户，每个启用的网络必须至少配置一个 EAP-MSCHAPv2 用户。保存后会自动启动、停止或热加载 IKEv2 服务；页面同时提供 CA 下载和 Windows、macOS/iOS、Android、strongSwan 接入步骤。

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
