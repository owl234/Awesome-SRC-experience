# Web服务器渗透测试经验

## 文章测试流程

[Web服务器渗透测试：利用Apache Struts2 S2-016(CVE-2013-2251) 漏洞获得RCE](../Web%E6%9C%8D%E5%8A%A1%E5%99%A8%2FWeb%E6%9C%8D%E5%8A%A1%E5%99%A8%E6%B8%97%E9%80%8F%E6%B5%8B%E8%AF%95%EF%BC%9A%E5%88%A9%E7%94%A8Apache%20Struts2%20S2-016%28CVE-2013-2251%29%20%E6%BC%8F%E6%B4%9E%E8%8E%B7%E5%BE%97RCE.md)：

```mermaid
graph LR
A(网络空间搜索引擎<br>搜集公司资产) --> |发现薄弱资产<br>非标准端口运行的Tomcat|B[端口扫描<br>资产识别] 
B --> |发现低版本<br>Tomcat|C[查找<br>相关漏洞] 
C --> |漏洞<br>利用|D[未成功] 
B --> |发现低版本<br>Tomcat|E[目录文件<br>模糊测试] 
E --> |发现目录<br>manager|F[密码爆破<br>Hydra] 
E --> |发现目录<br>manager|G[更换字典<br>模糊测试] 
F --> |爆破<br>失败|D 
G --> |发现<br>新资产|H[查找<br>敏感文件] 
H --> |发现<br>showLogin.action|I[查找<br>相关漏洞]
I --> |漏洞利用|J(获得<br>RCE)

```



