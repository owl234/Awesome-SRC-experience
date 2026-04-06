# 📝 SRC Experience Template

Use this template to contribute a new vulnerability research or bug hunting experience.

---
title: "Replace with a catchy Title"
description: "Brief summary of the vulnerability and its impact."
category: "e.g., Injection, Logic Flaw, Access Control"
difficulty: "Easy / Medium / Hard"
tags: ["tag1", "tag2"]
author: "Your Name/Handle"
date: "YYYY-MM-DD"
---

# 🛡️ [Vulnerability Name]: [High-Level Result]

> [!TIP]
> **核心战术**: [One sentence summary of the key technique or bypass.]

## 漏洞背景 (Context)
[Describe the target, the environment, and how you started your research.]

## 攻坚环节 (The Attack Chain)

### 1. 资产发现 (Discovery)
[How did you find the entry point?]

### 2. 漏洞利用 (Exploitation)
[Step-by-step reproduction. Use code blocks for Payloads.]

```http
GET /api/v1/user?id=1' OR '1'='1 HTTP/1.1
Host: target.com
```

### 3. 绕过思路 (Bypass Techniques)
[If applicable, describe what protections were in place and how you subverted them.]

## 💡 修复建议 (Remediation)
[How should the developer fix this permanently?]

---
*Reference: [Link to original post if applicable]*
