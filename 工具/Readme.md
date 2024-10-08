## :heart: Tools

为了给庞杂的渗透测试工具分类，我们简单将渗透测试流程抽象为以下几个模块：

![](../img/FlowChart.png)

每个工具会根据其优势，正确匹配到各个模块中，供大家针对性学习。

### :star: 端口扫描（Port scanning）

- [Naabu](https://github.com/projectdiscovery/naabu) ：一款用Go语言编写的端口扫描工具，能快速枚举主机上的有效端口。这是一个非常简单的工具，可对主机或主机列表执行快速SYN/CONNECT/UDP扫描并列出所有返回响应的端口。


### :eyeglasses:  指纹识别（Fingerprinting）

- [httpx](https://github.com/projectdiscovery/httpx) ：一款快速且多功能的HTTP工具包，支持使用retryablehttp库运行多个探针。旨在即使在使用多线程的情况下也能保持结果可靠性。可用于技术栈和Web服务器探测。

### :computer: 漏洞利用（Exploit）

- [Metasploit-framework](https://github.com/rapid7/metasploit-framework) : Metasploit-framework 是一组拥有信息收集、扫描、漏洞利用、漏洞挖掘、后渗透等的开源渗透测试框架，常用于漏洞利用和后渗透测试。

