---
title: "自动化兵器谱 (Modern Arsenal)"
description: "从资产发现到自动漏扫，整合一线 SRC 专家的自动化武器库。"
---

# 🛠️ 自动化兵器谱 (Modern Arsenal)

> [!TIP]
> **工具即杠杆**: 在现代 SRC 战场，速度决定收益。我们将渗透流程抽象为**自动化流水线**，每款工具都精准定位其在工程化中的坐标。

---

## 🛰️ 资产发现与指纹 (Recon & Fingerprinting)

| 工具名称 | 核心能力 | 实战坐标 |
| :--- | :--- | :--- |
| **[Naabu](https://github.com/projectdiscovery/naabu)** | 极速端口枚举 | SYN/CONNECT 扫描，快速锁定开放服务 |
| **[httpx](https://github.com/projectdiscovery/httpx)** | 多维指纹识别 | 探测技术栈、Web 容器版本，配合 retryablehttp 保证高并发 |
| **[ParamSpider](https://github.com/devanshbatham/ParamSpider)** | 隐藏参数挖掘 | 从 Wayback Machine 等存档提取 URL，为 Fuzzing 提供弹药 |

---

## 🧬 带外测试与漏洞捕获 (OOB & Detection)

- **[Interactsh](https://app.interactsh.com/)**: 开源带外数据提取方案。检测 Blind SQLi, SSRF, CMDi 的金标准。
- **[EYES](https://github.com/lijiejie/eyes.sh)**: 深度优化的 DNSLog/HTTPLog 检测工具，适配国内主流扫描器。

---

## 🔫 漏洞扫描与自动投弹 (Vuln Scanning)

### [Nuclei](https://github.com/projectdiscovery/nuclei) 
**SRC 自动化的灵魂。** 基于 YAML 模板的扫描器，支持 TCP/DNS/HTTP/Websocket 全协议。
-   *实战建议*: 维护一套自己的私有模板库，是冲击排行榜的关键。

### [afrog](https://github.com/zan8in/afrog)
高性能漏洞扫描利器。内置大量 CVE, CNVD 以及针对国内大厂的未授权访问 PoC。

---

## ⚡ 自动发现流 (Auto-Discovery Pipeline)

> [!IMPORTANT]
> **[Netlas 侦察自动化 + Nuclei 自动扫描](./auto-discovery/netlas-nuclei-auto.md)**
> 深度整合 Netlas API 与 Python 脚本，实现从“子域发现”到“全自动化投弹”的端到端闭环。

---

> [!CAUTION]
> **安全声明**: 兵器库仅供合法的安全研究与 SRC 授权测试使用。请遵守相关法律法规，拒绝非法攻击。
