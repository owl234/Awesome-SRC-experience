---
title: "SMS Bomb: Logic Flaw in WeChat Mini-Program"
description: "How a bypass in the standard login flow allowed for unrestricted SMS message delivery."
category: "Logic Flaw"
difficulty: "Easy"
tags: ["SMS-Bomb", "WeChat", "Mini-Program", "Rate-Limiting"]
author: "Community Contributor"
date: "2026-04-06"
target_type: "web"
---

# 🛡️ 微信小程序逻辑漏洞：绕过限制实现“短信轰炸”

> [!TIP]
> **漏洞核心**: 业务逻辑分支不一致。系统在“微信一键登录”流程中设置了频率限制，但在“手机号/其他方式登录”的可选分支中，由于缺少图形验证码深度校验或会话绑定缺失，导致限制被绕过。

## 漏洞产生点

**资产**: 某知名品牌微信小程序登录页面。

## 攻击链分析：寻找防御缺口

### 1. 正常业务流 (受限)
用户进入登录页 -> 授权手机号 -> 服务端校验频率 -> 发送短信。此流程中，服务端对频率有严格监控。

### 2. 漏洞绕过流 (无限制)
用户进入登录页 -> **拒绝**授权手机号 -> 点击“使用其他手机号登录” -> 输入目标手机号 -> 手动触发短信发送。

由于“手动输入”分支的图形验证码校验逻辑与短信发送逻辑未进行强关联，通过重放请求，可以实现对任意手机号的批量短信冲击。

## 实战复盘

![](/img/640.png)
*图 1: 手动输入手机号的入口，防护层级显著低于一键授权。*

![](/img/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20241105232010.png)
*图 2-4: 演示了通过不同手机号或重发请求实现的批量发送效果。*

## 💡 修复建议

- **统一鉴权网关**: 确保所有登录分支（一键登录、手动登录、验证码登录）共享同一个**速率限制器（Rate Limiter）**。
- **验证码强绑定**: 短信发送请求必须携带通过校验的图形验证码 Token，且该 Token 必须与当前 Session 绑定。
- **指纹限制**: 除了手机号维度，还应增加对 IP、设备指纹等维度的多重频率控制。

---
*参考来源: [微信公众号文章](https://mp.weixin.qq.com/s/8mgOzhc2PeQPAuXrT5vY8Q)*
