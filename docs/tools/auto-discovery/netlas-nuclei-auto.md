---
title: 'Netlas侦察自动化+Nuclei自动扫描'
description: 'Awesome SRC Experience - Netlas侦察自动化+Nuclei自动扫描'
---

# Netlas 侦察自动化+Nuclei 自动扫描

![](/img/1_--5o3oamKsoGyyuPNPqwgw.webp)

Netlas 是一个新工具，提供多种服务，如 IP WHOIS 查询、DNS 查询、攻击面发现、证书搜索、响应搜索等。它是一个很好的 Shodan 替代品。

Netlas 还有大量搜索技巧 (dorking facilities)。在这片文章中，我们将利用 Netlas 的 Python 库，通过 Nuclei 模板，自动扫描某个域名下的所有子域名漏洞。

## Neuro 项目 Github 仓库

https://github.com/humblelad/neuro
通过 Neuro，我们实现了端到端的自动化流程，将 Netlas API 与 Nuclei 模板扫描器结合，从而发现开放漏洞。

请确保在你的漏洞扫描器中安装了 httpx、Nuclei 和 Netlas Python 依赖。如果按照文档中的步骤操作，这个过程非常简单。

![](/img/1_p6jfLD21f-OcyNWphIawuA.webp)

**httpx** 安装方法：

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

**nuclei** 安装方法：

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Netlas** Python 库

用于下载子域名并获取活动子域名。Netlas Python 代码库地址：[https://github.com/netlas-io/netlas-python](https://github.com/netlas-io/netlas-python)

安装方法：

```bash
pip3 install netlas
```

从 Netlas 仪表盘获取 API 密钥，并将其放入 Python 脚本中，然后运行 `./run.sh` 脚本，并输入要使用 Neuro 扫描的域名。

目前，脚本会扫描所有严重型和高危型的漏洞模板，并发请求数量为 50。你可以根据自己的需要和业务需求来处理这些结果。例如：

- 将扫描结果保存到文件中。

- 创建 cron 任务自动运行 Python 脚本

- 设置 Slack 通知以接收扫描结果更新。

注意：运行 shell 脚本时，请确保所有相关的 Python 脚本 (。py 文件) 和文本文件 (。txt 文件) 都位于同一个文件夹中。

```bash
#!/bin/bash
#automate netlas nuclei scan

# Run python3 main.py
python3 main.py

# Check if python3 main.py ran successfully
if [[ $? -ne 0 ]]; then
  echo "python3 main.py failed to run successfully."
  exit 1
fi

#httpx
cat lol.txt | ./httpx > output.txt

if [[ $? -ne 0 ]]; then
  echo "Failed"
  exit 1
fi

# Run nuclei
nuclei -l output.txt -v -severity high,critical -c 50
```
