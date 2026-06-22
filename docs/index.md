---
layout: home
---

<div class="apple-canvas">

<!-- 顶部区域：紧凑型 Hero + 宣言 -->
<section class="apple-hero-compact">
<div class="hero-title">重新定义实战。</div>
<div class="hero-subtitle">Awesome SRC。专注漏洞挖掘的终极经验库。</div>
<div class="manifesto-text">我们抛弃繁杂的理论。这里只留下最锋利的代码、最高效的兵器，和真实的血肉经验。</div>
<div class="hero-action">
<a class="hero-button" href="/Awesome-SRC-experience/experience/README.html">开启进阶之旅 <span>↗</span></a>
<a class="hero-link" href="/Awesome-SRC-experience/tools/Readme.html">浏览兵器谱</a>
</div>
</section>

<!-- 底部区域：三栏并排 (无边框极简) -->
<section class="apple-pillars-compact">

<div class="pillar">
<div class="pillar-h2">Web / IoT / Cloud</div>
<div class="pillar-h3">直击核心战场</div>
<div class="pillar-p">不再纸上谈兵。每一篇都是真实的漏洞复盘，带你从硬件边界一路突破到云原生基础设施。</div>
</div>

<div class="pillar">
<div class="pillar-h2">自动化赋能</div>
<div class="pillar-h3">降维打击</div>
<div class="pillar-p">全面融合 AI 大模型与 LangGraph 智能体，打造下一代的自动化安全引擎。</div>
</div>

<div class="pillar">
<div class="pillar-h2">0 配置共建</div>
<div class="pillar-h3">即刻发布</div>
<div class="pillar-p">忘记复杂的框架。只要提交一段干净的 Markdown，自动化引擎即可秒级发布、全球共享。</div>
</div>

</section>

</div>

<style>
/* 隐藏 VitePress 默认主页的冗余结构 */
.VPHero, .VPFeatures { display: none !important; }

.apple-canvas {
  width: 100%;
  height: calc(100vh - var(--vp-nav-height));
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  overflow: hidden;
  color: var(--vp-c-text-1);
  padding: 0 24px;
  box-sizing: border-box;
}

/* ============================
   Top: Compact Hero
   ============================ */
.apple-hero-compact {
  text-align: center;
  margin-bottom: 64px;
  max-width: 800px;
}

.hero-title {
  font-size: clamp(3rem, 6vw, 4.5rem);
  font-weight: 800;
  letter-spacing: -0.04em;
  line-height: 1.1;
  margin: 0 0 16px 0 !important;
  background: linear-gradient(180deg, var(--vp-c-text-1) 0%, var(--vp-c-text-2) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.hero-subtitle {
  font-size: clamp(1.2rem, 2vw, 1.5rem);
  font-weight: 600;
  color: var(--vp-c-text-1);
  margin: 0 0 16px 0 !important;
  letter-spacing: -0.02em;
}

.manifesto-text {
  font-size: clamp(1rem, 1.5vw, 1.125rem);
  font-weight: 400;
  line-height: 1.5;
  color: var(--vp-c-text-2);
  margin: 0 0 32px 0 !important;
}

.hero-action {
  display: flex;
  gap: 24px;
  justify-content: center;
  align-items: center;
}

.hero-button {
  display: inline-flex;
  align-items: center;
  font-size: 1.05rem;
  font-weight: 600;
  color: #ffffff !important;
  background: linear-gradient(120deg, #bd34fe 30%, #41d1ff);
  padding: 12px 32px;
  border-radius: 32px;
  text-decoration: none !important;
  transition: transform 0.2s, opacity 0.2s, box-shadow 0.2s;
  box-shadow: 0 4px 14px 0 rgba(65, 209, 255, 0.3);
}

.hero-button span {
  margin-left: 6px;
  transition: transform 0.2s;
}

.hero-button:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(65, 209, 255, 0.5);
  opacity: 1;
}

.hero-button:hover span {
  transform: translateX(4px);
}

.hero-link {
  font-size: 1rem;
  font-weight: 600;
  color: var(--vp-c-brand-1);
  text-decoration: none !important;
}

.hero-link:hover {
  text-decoration: underline !important;
}

/* ============================
   Bottom: 3 Pillars Grid
   ============================ */
.apple-pillars-compact {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 40px;
  max-width: 1024px;
  width: 100%;
}

.pillar {
  text-align: left;
}

.pillar-h2 {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--vp-c-text-3);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin: 0 0 8px 0 !important;
}

.pillar-h3 {
  font-size: clamp(1.5rem, 2vw, 1.75rem);
  font-weight: 700;
  color: var(--vp-c-text-1);
  letter-spacing: -0.02em;
  line-height: 1.2;
  margin: 0 0 12px 0 !important;
}

.pillar-p {
  font-size: 0.95rem;
  color: var(--vp-c-text-2);
  line-height: 1.6;
  margin: 0 !important;
}

/* Responsive constraints to keep it one screen */
@media (max-height: 700px) {
  .apple-hero-compact {
    margin-bottom: 40px;
  }
  .hero-title {
    font-size: 3rem;
  }
  .apple-pillars-compact {
    gap: 24px;
  }
}

/* Mobile fallback */
@media (max-width: 768px) {
  .apple-canvas {
    height: auto;
    overflow-y: auto;
    padding: 64px 24px;
  }
  .apple-pillars-compact {
    grid-template-columns: 1fr;
    gap: 48px;
  }
  .pillar {
    text-align: center;
  }
}
</style>
