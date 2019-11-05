## RTLS

RTLS 是一个可以自动部署证书的tls代理，用于多节点的证书分发。

Let's Encrypt 的泛域名证书需要使用DNS验证，以及一些节点无法接听80、443时候也无法使用HTTP验证方式，因而难于自动部署证书。此软件可以动态动态的从一个中心证书网站更新指定的证书，由此来实现证书的分法。

### 证书中心配置

可以使用[CertDistribution](https://github.com/Catofes/CertDistribution)来作为证书中心网站。抑或一个实现了如下HTTP请求的网站。

``` GET /{{uuid}}/wait/{{cert-serial-number}} ```

该请求应该是一个阻塞调用，并在证书有更新且`serial-number`变化时候返回新证书。其中`serial-number`应为`big int`转化的10进制字符串。

### 配置示例

```
{
	"Listen": "0.0.0.0:443",
	"CertsPath": "./certs",
	"Debug": true,
	"LogBufferLen": 10000,
	"Rules": [
		{
			"a.example.com":"tls://a.cert@www.google.com:443"
		},
        {
            "^(.+\\.|)b.example.com$":"tcp://b.cert@127.0.0.1:80"
        },
        {
            "^(.+\\.|)c.example.com$":"direct://www.google.com:443"
        }
	],
	"Certs":{
		"a.cert": {
			"UUID": "d6ee5e46-d159-cccc-aaaa-bbbbbbbbbbbb"
		}
        "b.cert": {
            "UUID": "d6ee5e46-d159-cccc-aaaa-dddddddddddd"
        }
	}
}
```

可以通过配置文件中的`"CertGateway":"https://your.cert.center"`来制定证书中心网址。

`Rules`指定了转发规则，`key`为匹配`host`的正则表达式，`value`为目标地址， 格式为 `[protol]://[certName]:[SNI]@[Host]:[Port]`。 tls即通过加密tls连接后端（会忽略证书错误），tcp直接不加密连接。direct直接通过sni转发请求，不做tls的握手解析。