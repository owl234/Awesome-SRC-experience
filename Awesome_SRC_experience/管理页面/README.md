# 管理页面渗透测试经验

## 文章漏洞测试流程图

[子域名模糊测试：管理页面前端验证绕过拿下SQL，升级RCE](./子域名模糊测试：管理页面前端验证绕过拿下SQL，升级RCE.md)：

```mermaid
graph LR
B(管理页面<br>子域名模糊测试) --> |发现子域名<br>admintest.Target.com|C[敏感<br>文件检查] 
C -->|发现敏感文件<br>/admin/main.aspx| D[HTTP前端<br>验证绕过]
D -->|拿下管理<br>系统权限| E[敏感<br>文件检查]
E -->|发现<br>SQLQuery.aspx| F[升级<br>SQL注入]
F -->|利用<br>xp_cmdshell| G(升级RCE)
```



