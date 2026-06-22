---
title: '参与共建'
description: 'Awesome SRC Experience - 极简文档提交流'
sidebar: false
---

<style scoped>
.contribute-container {
  max-width: 800px;
  margin: 0 auto;
  padding: 40px 20px;
  text-align: center;
}

.contribute-title {
  font-size: 2.5rem;
  font-weight: 800;
  margin-bottom: 20px;
  background: -webkit-linear-gradient(120deg, #bd34fe 30%, #41d1ff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.contribute-desc {
  font-size: 1.2rem;
  color: var(--vp-c-text-2);
  margin-bottom: 40px;
  line-height: 1.6;
}

.action-buttons {
  display: flex;
  justify-content: center;
  gap: 20px;
  margin-bottom: 60px;
  flex-wrap: wrap;
}

.btn-primary {
  display: inline-block;
  padding: 12px 28px;
  border-radius: 8px;
  background-color: var(--vp-button-brand-bg);
  color: var(--vp-button-brand-text);
  font-weight: 600;
  text-decoration: none;
  transition: all 0.25s;
}

.btn-primary:hover {
  background-color: var(--vp-button-brand-hover-bg);
  transform: translateY(-2px);
}

.btn-secondary {
  display: inline-block;
  padding: 12px 28px;
  border-radius: 8px;
  background-color: var(--vp-button-alt-bg);
  color: var(--vp-button-alt-text);
  font-weight: 600;
  text-decoration: none;
  transition: all 0.25s;
}

.btn-secondary:hover {
  background-color: var(--vp-button-alt-hover-bg);
  transform: translateY(-2px);
}
</style>

<div class="contribute-container">

  <h1 class="contribute-title">提交你的实战兵法</h1>
  <p class="contribute-desc">
    忘记复杂的框架和难用的后台。只要你会写 Markdown，只需在网页上点一点，你的漏洞挖掘经验即可秒级发布，与全球白帽子共享。
  </p>

  <div class="action-buttons">
    <a href="https://github.com/owl234/Awesome-SRC-experience/new/main/docs/experience/web/xss" target="_blank" class="btn-primary">
      🚀 提交一条实战经验
    </a>
    <a href="https://github.com/owl234/Awesome-SRC-experience/new/main/docs/tools/vuln-scanners" target="_blank" class="btn-secondary">
      🛠️ 提交一个自动化兵器
    </a>
  </div>

</div>

::: info 📋 请在文章顶部携带这段模板 (Frontmatter)
我们的极简引擎通过读取这段代码，会自动将你的文章排版并分类到左侧边栏中。请一键复制并粘贴到你文章的**最顶部**：

```yaml
---
title: "你的文章大标题（会在侧边栏显示）"
description: "一句话简述文章内容"
author: "你的安全圈 ID"
difficulty: "Medium" # 难度：Easy, Medium, Hard
---

# 文章正文标题
... 这里开始写你的奇淫技巧 ...
```

:::

<br>

> [！TIP]
> **💡 小提示**
>
> 1. 上方的按钮会唤起 GitHub 的在线代码编辑器。
> 2. 在上方 URL 路径栏中，你可以将 `xss` 改为你想要的任何标准漏洞分类 (如 `rce`，`logic-flaw` 等)，如果分类目录不存在，系统会自动为你创建！
> 3. 写完后，点击右上角的绿色按钮 **Commit changes**，提出 Pull Request，管理员审核通过后网站即刻更新。
