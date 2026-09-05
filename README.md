# vnts

[vnt](https://github.com/vnt-dev/vnt)的服务端


## 说明

1. 支持quic、tcp(tls)和wss协议，会自动生成自签名证书，也可以手动替换
2. 无参数启动后，会输出配置文件，可以修改配置文件
3. --conf-example 参数查看配置文件示例
4. 可选启用内置 IKEv2/IPsec（UDP 500/4500），让系统原生 VPN 客户端以独立设备加入指定 VNT 网络

## IKEv2/IPsec

推荐先在 Web 管理端的“系统设置 → IKEv2/IPsec 基础配置”设置监听、服务器地址、远程ID和证书，再到“网络详情 → 新增设备”创建 IKEv2 类型设备。服务器地址是生成接入步骤时提供给客户端的单个连接地址；远程ID是服务端 IKE 身份并用于匹配证书。每台 IKEv2 客户端使用独立的用户名和密码，用户名同时作为设备 ID。没有 `[ikev2]` 时页面会提供默认监听值；cert/key 留空会自动建立本地 CA，并签发匹配域名或 IPv4 远程ID的 RSA-2048 服务器证书。也可以填写自定义证书链和私钥路径。ESP 数据面统一使用 UDP/4500 NAT-T。

IKEv2 客户端从对应网络的地址池获取虚拟 IP，并可跨互联服务端通信；启用了 `white_list` 时也要包含这些网络编号。普通 VNT 节点必须显式配置 `allow_ikev2 = true` 才会看到并接受 IKEv2 流量。

系统设置可编辑服务开关、UDP 500/4500 监听、服务器地址、远程ID、DNS 和证书路径；网络详情的设备列表负责管理 IKEv2 设备及凭据。保存全局设置后会自动启动、停止或热加载 IKEv2 服务；每个 IKEv2 设备的操作栏提供 CA 下载和 Windows、macOS/iOS、Android、strongSwan 接入步骤。

客户端只支持 EAP-MSCHAPv2 用户名/密码认证：连接地址使用 `server_address`，服务器身份使用 `remote_id`，用户名和密码来自对应 IKEv2 设备的接入说明，并在系统中信任签发 IKE 证书的 CA。Android 必须在 VPN 配置的“IPSec CA 证书”中明确选择该 CA，不能选择“不验证服务器”；其原生客户端默认发送空的 outer EAP Identity，服务端会在后续 MSCHAPv2 Response 中按用户名选择设备凭据。Windows 原生客户端需把 IKE/ESP 加密算法配置为 `GCMAES256`、DH 组配置为 Group14。


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
