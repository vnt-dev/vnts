# vnts

[vnt](https://github.com/vnt-dev/vnt)的服务端

查看参数

```
Options:
  -p, --port <PORT>                指定端口，默认29872
  -w, --white-token <WHITE_TOKEN>  token白名单，例如 --white-token 1234 --white-token 123
  -g, --gateway <GATEWAY>          网关，例如 --gateway 10.10.0.1
  -m, --netmask <NETMASK>          子网掩码，例如 --netmask 255.255.255.0
  -f, --finger                     开启指纹校验，开启后只会转发指纹正确的客户端数据包，增强安全性，这会损失一部分性能
  -l, --log-path <LOG_PATH>        log路径，默认为当前程序路径，为/dev/null时表示不输出log
      --wg <WG_SECRET_KEY>         wg私钥，使用base64编码
  -h, --help                       Print help information
  -V, --version                    Print version information
```

## 说明

1. 修改服务端密钥后，客户端要重启才能正常链接(修改密钥后无法自动重连)
2. 服务端密钥用于加密客户端和服务端之间传输的数据(使用rsa+aes256gcm加密)
   ，可以防止token被中间人窃取，如果客户端显示的密钥指纹和服务端的不一致，则表示可能有中间人攻击
3. 服务端密钥在'./key/'目录下,可以替换成自定义的密钥对
4. 客户端的密码用于加密客户端之间传输的数据
5. 默认情况服务日志输出在 './log/'下,可通过编写'
   ./log/log4rs.yaml'文件自定义日志配置,参考[log4rs](https://github.com/estk/log4rs)

## 编译

前提条件:安装rust编译环境([install rust](https://www.rust-lang.org/zh-CN/tools/install))

```
到项目根目录下执行 cargo build

web是可选模块，如需编译则使用 cargo build --features web

```

## 环境变量映射表
将 vnts 参数转换为环境变量（全部大写，前缀 VNT_）：

参数	环境变量名	示例值
-p/--port	VNT_PORT	29872

-w/--white-token	VNT_WHITE_TOKEN	mysecrettoken

-g/--gateway	VNT_GATEWAY	10.10.0.1

-m/--netmask	VNT_NETMASK	255.255.255.0

-f/--finger	VNT_FINGER	true

-l/--log-path	VNT_LOG_PATH	/var/log/vnt.log

-P/--web-port	VNT_WEB_PORT	29870

-U/--username	VNT_USERNAME	admin

-W/--password	VNT_PASSWORD	securepass123

--wg	VNT_WG_SECRET_KEY	base64_encoded_key
