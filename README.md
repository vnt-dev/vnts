# vnts
[vnt](https://github.com/lbl8603/vnt)的服务端 

查看参数
```
Options:
      --port <PORT>                指定端口
      --white-token <WHITE_TOKEN>  token白名单，例如 --white-token 1234 --white-token 123
      --gateway <GATEWAY>          网关，例如 --gateway 10.10.0.1
      --netmask <NETMASK>          子网掩码，例如 --netmask 255.255.255.0
  -h, --help                       Print help
```

## 说明
1. 修改服务端密钥后，客户端要重启才能正常链接(修改密钥后无法自动重连)
2. 服务端密钥用于加密客户端和服务端之间传输的数据(使用rsa+aes256gcm加密)，可以防止token被中间人窃取，如果客户端显示的密钥指纹和服务端的不一致，则表示可能有中间人攻击
3. 服务端密钥在'./key/'目录下,可以替换成自定义的密钥对
4. 客户端的密码用于加密客户端之间传输的数据
5. 默认情况服务日志输出在 './log/'下,可通过编写'./log/log4rs.yaml'文件自定义日志配置,参考[log4rs](https://github.com/estk/log4rs)
