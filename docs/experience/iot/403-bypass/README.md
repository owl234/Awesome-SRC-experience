---
title: "403-bypass渗透测试经验"
description: "Awesome SRC Experience - 403-bypass渗透测试经验"
---

# 403-bypass渗透测试经验

## 文章漏洞测试流程图

[403-bypass绕过：拿到P1漏洞！](./403-bypass.md) :

```mermaid
graph LR
A(目录枚举)-->|发现403-bypass<br>/console|B[403绕过]
B-->|拿下控制台管理器|C[敏感<br>信息检查]
C-->|发现<br>用户代码执行（CLI）组件|D(升级<br>RCE)
```

