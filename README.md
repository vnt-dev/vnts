# vnts

[vnt](https://github.com/vnt-dev/vnt)的服务端


## 说明

1. 支持quic、tcp(tls)和wss协议，会自动生成自签名证书，也可以手动替换
2. 无参数启动后，会输出配置文件，可以修改配置文件
3. --conf-example 参数查看配置文件示例


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
