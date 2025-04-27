# 定义可变参数：默认 target 是 x86_64-unknown-linux-musl
ARG BUILD_TARGET=x86_64-unknown-linux-musl

# 构建阶段 - 使用官方 Rust 镜像
FROM rust:1.70 as builder

# 重新声明 ARG（因为每个阶段都得重新声明）
ARG BUILD_TARGET

# 配置阿里云镜像加速 (更新为兼容格式)
RUN mkdir -p /usr/local/cargo \
    && echo '[source.crates-io]\n\
replace-with = "aliyun"\n\
\n\
[source.aliyun]\n\
registry = "sparse+https://mirrors.aliyun.com/crates.io-index/"' > /usr/local/cargo/config

# 安装编译依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# 安装 musl 工具链（针对 musl）
RUN rustup target add ${BUILD_TARGET}
RUN apt-get update && apt-get install -y musl-tools

WORKDIR /app

# 克隆项目
RUN git clone https://github.com/hotwa/vnts-docker \
    && cd vnts-docker \
    && git submodule update --init

# 构建带 Web 功能的版本 (静态链接)
RUN cd vnts-docker \
    && cargo build --release --target ${BUILD_TARGET} --features web

# 运行时阶段 - 使用 Alpine
FROM alpine:3.18

# 重新声明 ARG（虽然这里用不到，但可以做记录）
ARG BUILD_TARGET

# 安装运行时依赖
RUN apk add --no-cache libgcc openssl

# 创建目录结构
RUN mkdir -p /app/key /app/log

# 只复制必要的可执行文件和运行时资源
COPY --from=builder /app/vnts-docker/target/${BUILD_TARGET}/release/vnts /app/
COPY --from=builder /app/vnts-docker/static /app/static/  

# 环境变量默认值
ENV VNT_PORT=29872 \
    VNT_WEB_PORT=29870 \
    VNT_USERNAME=admin \
    VNT_PASSWORD=admin \
    VNT_LOG_PATH=/app/log/vnt.log

# 暴露端口
EXPOSE $VNT_PORT/tcp $VNT_PORT/udp $VNT_WEB_PORT/tcp

# 启动命令
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# 使用 exec 形式确保信号传递
ENTRYPOINT ["/app/entrypoint.sh"]
