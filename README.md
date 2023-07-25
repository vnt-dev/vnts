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
默认情况服务日志输出在 './log/'下,可通过编写'./log/log4rs.yaml'文件自定义日志配置,参考[log4rs](https://github.com/estk/log4rs)
