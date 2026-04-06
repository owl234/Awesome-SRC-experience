---
layout: home

hero:
  name: "Awesome SRC"
  text: "安全攻防 · 经验倍增器"
  tagline: "从 0 到 1 的实战演练 · 职业级漏洞复盘 · 自动化兵器库"
  image:
    src: /img/hero.png
    alt: Awesome SRC Experience
  actions:
    - theme: brand
      text: 🚀 开启进阶之旅
      link: /experience/README
    - theme: alt
      text: 🛠️ 浏览兵器谱
      link: /tools/Readme

features:
  - title: 🛡️ 职业级复盘
    details: 拒绝碎片化笔记。每篇文档均遵循“战术背景、攻坚环节、防御闭环”标准，建立专家级渗透逻辑。
  - title: ⚡ 自动化优先
    details: 深度整合实战 Payloads。从人肉测试转向工程化自动扫描，让效率成为你的核心竞争力。
  - title: 🌐 0 摩擦共建
    details: 物理架构与侧边栏自动映射。无需繁琐配置，提交 Markdown 即刻发布全球，共享安全智慧。
---

<div class="content-container">

## 🎯 我们的使命

让每一位安全从业者都能像**顶尖白帽**一样思考。这不仅是一个文档库，更是一个**漏洞发现的思维加速器**。

<div class="roadmap-grid">
  <div class="roadmap-item">
    <h3>🔍 资产发现</h3>
    <p>从子域名枚举到隐蔽参数挖掘，不留死角。</p>
  </div>
  <div class="roadmap-item">
    <h3>🧪 漏洞演练</h3>
    <p>深度剖析 XSS, SQLi, Logic Flaws 等实战案例。</p>
  </div>
  <div class="roadmap-item">
    <h3>🤖 自动武器化</h3>
    <p>编写 Nuclei 模板，构建属于你的自动化扫描矩阵。</p>
  </div>
</div>

</div>

<style>
.content-container {
  max-width: 1152px;
  margin: 0 auto;
  padding: 64px 32px;
}
.content-container h2 {
  text-align: center;
  margin-bottom: 48px;
  font-size: 2.5rem;
  font-weight: 800;
  line-height: 1.3;
  padding: 0.1em 0;
  background: linear-gradient(135deg, #e0aaff, #9d4edd, #5a189a);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.roadmap-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
  margin-top: 32px;
}
.roadmap-item {
  padding: 24px;
  border-radius: 12px;
  background: rgba(157, 78, 221, 0.05);
  border: 1px solid rgba(157, 78, 221, 0.1);
  transition: all 0.3s ease;
}
.roadmap-item:hover {
  transform: translateY(-5px);
  background: rgba(157, 78, 221, 0.1);
  border-color: #9d4edd;
  box-shadow: 0 10px 40px rgba(157, 78, 221, 0.15);
}
.roadmap-item h3 {
  color: #9d4edd;
  margin-bottom: 12px;
}
</style>
