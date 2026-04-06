---
layout: home

hero:
  name: "Awesome SRC"
  text: "精英级攻防 · 经验倍增器"
  tagline: "从 1 到 100 的实战进阶 · 全平台漏洞复盘 · 自动化兵器库"
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
  - title: 🎯 Target 导向分类
    details: 按物联网 (IoT)、Web 应用、云安全、关键基础设施进行分类，精准定位实战场景。
  - title: ⚔️ 实战兵器谱
    details: 深度整合 Nuclei, Interactsh 与自定义 Payloads，将手工作业提升为自动化工程。
  - title: 🌐 零冲突共建
    details: 基于 Target 拓扑的自动化索引。无需配置，提交 Markdown 即刻发布，全球共享。
---

<div class="content-container">

## 🧩 攻防全景图 (ROADMAP)

<div class="roadmap-grid">
  <div class="roadmap-item iot">
    <h3>📡 IoT & Device</h3>
    <p>固件分析、协议逆向、未授权访问。从硬件边界突破企业内网。</p>
    <div class="tag">HIGH IMPACT</div>
  </div>
  <div class="roadmap-item web">
    <h3>🌐 Web & App</h3>
    <p>403 绕过、逻辑缺陷、SSRF、链式注入。主流 SRC 的核心战场。</p>
    <div class="tag">P1 FOCUSED</div>
  </div>
  <div class="roadmap-item cloud">
    <h3>☁️ Cloud & Infra</h3>
    <p>元数据泄露、S3 桶接管、K8s 逃逸。云原生时代的攻防新前线。</p>
    <div class="tag">MODERN TECH</div>
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
  background: linear-gradient(135deg, #39ff14, #9d4edd);
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
  padding: 32px 24px;
  border-radius: 16px;
  background: rgba(10, 10, 15, 0.8);
  border: 1px solid rgba(157, 78, 221, 0.2);
  transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  position: relative;
  overflow: hidden;
}
.roadmap-item:hover {
  transform: translateY(-8px);
  border-color: #39ff14;
  box-shadow: 0 10px 40px rgba(57, 255, 20, 0.15);
}
.roadmap-item h3 {
  color: #39ff14;
  margin-bottom: 12px;
  font-weight: 700;
  letter-spacing: 1px;
}
.roadmap-item p {
  font-size: 0.95rem;
  color: #a1a1aa;
  line-height: 1.6;
}
.roadmap-item .tag {
  position: absolute;
  top: 12px;
  right: 12px;
  font-size: 0.65rem;
  font-weight: 900;
  padding: 2px 8px;
  border-radius: 4px;
  background: rgba(57, 255, 20, 0.1);
  color: #39ff14;
  border: 1px solid rgba(57, 255, 20, 0.3);
}
.roadmap-item.iot { border-left: 4px solid #39ff14; }
.roadmap-item.web { border-left: 4px solid #9d4edd; }
.roadmap-item.cloud { border-left: 4px solid #00d4ff; }
</style>
