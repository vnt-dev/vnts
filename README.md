# vnts
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/vnt-dev/vnts)

[vnt](https://github.com/vnt-dev/vnt)的服务端


## 说明

1. 支持quic、tcp(tls)和wss协议，会自动生成自签名证书，也可以手动替换
2. 无参数启动后，会输出配置文件，可以修改配置文件
3. --conf-example 参数查看配置文件示例
4. 可选启用内置 IKEv2/IPsec（UDP 500/4500），让系统原生 VPN 客户端以独立设备加入指定 VNT 网络
5. 可选启用内置 WireGuard（默认 UDP 51820），生成标准客户端配置并作为独立设备加入 VNT 网络

## IKEv2/IPsec

推荐先在 Web 管理端的“系统设置 → IKEv2/IPsec 基础配置”设置监听、服务器地址、远程ID和证书，再到“网络详情 → 新增设备”创建 IKEv2 类型设备。服务器地址是生成接入步骤时提供给客户端的单个连接地址；远程ID是服务端 IKE 身份并用于匹配证书。每台 IKEv2 客户端使用独立的用户名和密码，用户名同时作为设备 ID。没有 `[ikev2]` 时页面会提供默认监听值；cert/key 留空会自动建立本地 CA，并签发匹配域名或 IPv4 远程ID的 RSA-2048 服务器证书。也可以填写自定义证书链和私钥路径。ESP 数据面统一使用 UDP/4500 NAT-T。

IKEv2 客户端从对应网络的地址池获取虚拟 IP，并可跨互联服务端通信；启用了 `white_list` 时也要包含这些网络编号。普通 VNT 节点必须显式配置 `allow_ikev2 = true` 才会看到并接受 IKEv2 流量。

系统设置可编辑服务开关、UDP 500/4500 监听、服务器地址、远程ID、DNS 和证书路径；网络详情的设备列表负责管理 IKEv2 设备及凭据。保存全局设置后会自动启动、停止或热加载 IKEv2 服务；每个 IKEv2 设备的操作栏提供 CA 下载和 Windows、macOS/iOS、Android、strongSwan 接入步骤。

客户端只支持 EAP-MSCHAPv2 用户名/密码认证：连接地址使用 `server_address`，服务器身份使用 `remote_id`，用户名和密码来自对应 IKEv2 设备的接入说明，并在系统中信任签发 IKE 证书的 CA。Android 必须在 VPN 配置的“IPSec CA 证书”中明确选择该 CA，不能选择“不验证服务器”；其原生客户端默认发送空的 outer EAP Identity，服务端会在后续 MSCHAPv2 Response 中按用户名选择设备凭据。Windows 原生客户端创建 VPN 时可将连接名称填写为 `VNT-IKEv2`。接入说明中的第一条 PowerShell 命令用于配置与服务端匹配的 IKE/ESP 加密算法和 DH 组；第二条命令 `Set-VpnConnection -Name "VNT-IKEv2" -SplitTunneling $true` 用于启用拆分隧道，仅将 VNT 虚拟网段流量送入 VPN，避免 VPN 接管系统默认路由。如果创建 VPN 时使用了其他连接名称，两条命令中的 `VNT-IKEv2` 也必须替换为相同名称。修改后需断开并重新连接 VPN。PPP 适配器显示 `/32` 子网掩码和 `0.0.0.0` 默认网关是点对点连接的正常表现。

## WireGuard

在 Web 管理端的“系统设置 → WireGuard 服务”中设置独立 UDP 监听地址和客户端可访问的公开 `Endpoint`。首次保存时会自动生成并持久化服务端私钥；管理 API 只公开对应公钥。

随后在网络详情中新增 `WireGuard` 类型设备。系统会自动生成并保存设备密钥，设备操作栏可随时查看、复制或下载标准 `.conf`。生成配置的 `AllowedIPs` 固定为该设备所属虚拟网段，不会接管默认路由。WireGuard 设备必须预先创建，未知公钥无法完成握手。

WireGuard、IKEv2 和 VNT 设备支持本地及跨服务端单播互通。普通 VNT 客户端必须在注册请求中设置 `allow_wireguard = true` 才会发现 WireGuard 设备并接受其流量；该开关与 `allow_ikev2` 相互独立。当前服务端支持 IPv4，暂不支持 WireGuard IPv6 和跨服务端广播。


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


## 远程连接组

网络新增 `group_type`，值为 `Network`（组网设备组，旧记录及省略字段时的默认值）或 `RemoteDesktop`（远程连接组）。原有 `network_type` 的 `Public` / `Private` 继续控制未知设备能否加入，两者相互独立。

远程桌面使用独立的 `REMOTE_DESKTOP` 客户端类型，只能进入远程连接组；普通 VNT、IKEv2、WireGuard 只能进入组网设备组。远程客户端首次使用不存在的编号注册时，在现有白名单限制下自动建立公开远程连接组。私有组需要预先添加远程桌面设备，支持设备订阅签发和在线配置更新。已有设备的组禁止切换用途。

网络创建 / 更新及列表 API 新增 `group_type` 字段；设备列表和服务器互联同步包含远程桌面客户端类型。数据库会自动添加独立的 `group_type` 列，保留原有公开 / 私有设置。多台互联服务端应同时升级并保持同编号组的用途一致。

远程连接组不配置网关、掩码、网络前缀或租期，设备使用 `connection_id`（1～9 位纯数字字符串），不再使用 IP 和 IP 类型。前导零保留，`001`、`0001` 不同，纯零编号合法。编号在同组内唯一，断线、租期清理及重启均不释放；删除设备或修改编号后释放旧绑定。

连接 ID 的内部 U32 编码为 `10^长度 + 数值`，例如 `001 → 1001`、`0001 → 10001`；数据库单独使用整数列存储。HTTP 接口使用字符串，远程注册、订阅及回执使用明确的连接 ID 字段。高级配置只接受通信、中继、打洞、STUN、加密和监听等参数，VPN 配置会被拒绝；`turn` 使用 `目标连接ID,中继连接ID`，`punch_model` 使用 `连接ID,打洞模式...`。

预配置远程组只需指定用途，无需在 `custom_nets` 中设置网段：

```toml
[group_types]
remote-office = "RemoteDesktop"
```

远程连接功能需与配套更新的 vnt-desk 一起部署；旧远程设备配置需要重新配置，不自动删除原有数据。普通组网设备组继续使用原有 IPv4、租期和 VPN 配置。
