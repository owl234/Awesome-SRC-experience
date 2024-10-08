# 子域名模糊测试：管理页面前端验证绕过拿下SQL，升级RCE

该文章的作者是**Abdullah Nawaf**，全职漏洞赏金猎人，在BugCrowd中排名前50，P1漏洞排名第11。

本文介绍了**如何使用子域名模糊测试和链接多个漏洞来获取完整的RCE（远程代码执行）漏洞。**

## 描述

2022年的时候，作者在Bugcrowd上报告了一个私人程序带的Auth Bypass导致SQLI&RCE，该漏洞在报告后一天就被修复。

2024年3月，作者决定重新测试他们的旧bug。他们的测试目标为：`admin.Target.com` 通过使用下面的命令进行子域模糊测试：

```bash
ffuf -w /subdomain_megalist.txt -u 'https://adminFUZZ.Target.com' -c  -t 350 -mc all  -fs 0
```

> 模糊测试字典：`subdomain_megalist.txt` 放在最后附录部分。

使用上述命令，作者发现了子域名：`admintest.Target.com`

![](././../../img/1_gJy6VL-cev_f7AJYhexNUA.jpg)

> 在图片中可以看到很多错误信息，但这没关系，因为在进行子域模糊测试时，错误信息表示这些子域名不可用。

`admintest.Target.com`很可能存在漏洞，因为它与原始子域`admin.Target.com`拥有相同的后端。 下面将逐个讨论作者发现的漏洞。

## 认证绕过（Auth Bypass）和浏览器自动完成（BAC）

`https://admintest.Target.com`被重定向到`https://admintest.Target.come/admin/login.aspx`

在阅读js文件时，我们发现了一个文件'https://admintest.Target.com/admin/main.aspx'。 直接在浏览器会再次重定向到登录页面，但在Burp中我们发现了一些有趣的东西。

![](./../../img/1_k8jW7uXrw6p-_-iphOWFYw.jpg)

重定向响应的`Content-Length` 大小异常的大（怀疑前端验证造成）。通过删除三个访问头，最终获得完全访问权限，至此打开访问面板。

![](./../../img/1_DOtsrYi_CHbtQMs_KB4KpQ.jpg)

使用Burp拦截响应，并修改以下访问头。

```html
将 302 Moved Temporarily 改为 200 OK
删除 Location: /admin/Login.aspx?logout=y
删除 html redirect code 
```

至此，作者成功实现了身份验证绕过，获得平台全部功能。随后通过深度挖掘，发现名为`adduser.aspx`的文件，该文件使用与`main.aspx`相同的技巧将访问重定向到登录页面。

利用上述相同的绕过方法，成功访问`adduser.aspx`页面并创建了一个管理员账户。 此外，还发现了一个无需身份验证即可显示**管理员密码和用户名**的地方。

![](./../../img/1_s1JhYLJSoteMFI30xYkZ_Q.jpg)

## SQL注入攻击

添加管理员账户后，就可以直接登录系统，这比使用认证绕过更方便。 随后，作者发现一个名为`SQLQuery.aspx`的端点，从名称就可以猜出它的功能。 首先，我尝试了以下的查询：

```sql
Select * from users;
```
结果，直接能看到所有用户的信息，包括密码、电子邮件和用户名。

## 远程代码执行（RCE）漏洞

由于数据库是`mssql`，作者尝试使用`xp_cmdshell`将其升级为RCE。

> `xp_cmdshell` 存储过程是 SQL Server 中的一个强大功能，可用于在 SQL 语句中执行系统命令。它允许数据库管理员或具有适当权限的用户直接从 SQL Server 访问操作系统功能。默认禁用，攻击者可以利用它来窃取敏感数据、安装恶意软件甚至完全控制系统。

简单来说，`xp_cmdshell` 允许用户通过`mssql`执行系统命令。 默认情况下，它是禁用的，但是可以轻松启用它。例如使用`sqlmap`工具的`--os-shell`参数。 不过这里能够直接向数据库发送查询，就无需使用`sqlmap`。 要让`xp_cmdshell`正常工作，我们首先需要使用以下查询启用它：

```sql
SP_CONFIGURE "show advanced options", 1
RECONFIGURE
SP_CONFIGURE "xp_cmdshell", 1
RECONFIGURE
```

然后，执行`xp_cmdshell 'whoami'` 拿下RCE漏洞。

![](./../../img/2.jpg)

作者将发现的多个问题整理成一份报告，并将另一个端点中发现的另一个SQL注入漏洞单独报告，最终获得了35000美元的赏金。

## 总结

1. **始终检查Burp中的重定向响应。**

作者发现了许多类似的身份验证绕过漏洞，作者第一次获得赏金是在2020年，利用的是相同的技巧：`/admin/admin.php`重定向到`login.php`。但是，当使用Burp查看响应时，发现`admin.php`页面可以正常工作，只是前端重定向。

2. **如果你在子域名中发现并修复了漏洞请尝试使用子域名模糊测试。**

**子域名模糊测试参考格式：**

```context
admin-FUZZ.target.com E.G: admin-stg.target.com
FUZZ-admin.target.com E.G: cert-admin.target.com
adminFUZZ.target.com  E.G: admintest.target.com
FUZZadmin.target.com  E.G  testadmin.target.com
admin.FUZZ.target.com E.G: admin.dev.target.com
```

**模糊测试命令：**

```bash
ffuf -w /subdomain_megalist.txt -u 'https://adminFUZZ.Target.com' -c  -t 350 -mc all  -fs 0

-t 线程数 , 根据你的t带宽设置，尽量不要设置太高，否则你可能会错过很多正常的子域名 , 
,作者使用vps将线程设置为 350 。

-mc all 代表匹配所有的响应码 比如 200,302,403 这一点非常重要。
```

3. **在提交报告之前尝试升级漏洞。**

4. **质量大于数量**

> 当你发现多个漏洞或将多个漏洞组合在一起时，请尝试将其作为一份报告提交，你将获得更高的赏金！

## 附录：

### 子域名爆破字典：

[subdomain_megalist.txt](https://github.com/netsecurity-as/subfuz/blob/master/subdomain_megalist.txt)

更多更大的字典：

[SecLists/Discovery/DNS ](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

## 使用的工具：

模糊测试神器：[ffuf](https://github.com/ffuf/ffuf)

Web安全测试神器：[Burp suite](https://portswigger.net/burp)

SQL注入检测和利用神器：[sqlmap](https://github.com/sqlmapproject/sqlmap)

