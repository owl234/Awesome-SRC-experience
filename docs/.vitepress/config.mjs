import { defineConfig } from 'vitepress'

export default defineConfig({
  title: "Awesome SRC Experience",
  description: "企业级 SRC 漏洞挖掘实战经验与自动化利器集合",
  srcExclude: ['**/Nuclei：使用Nuclei查找漏洞的终极指南.md', '**/Metasploit：Metasploit 入门.md'],
  themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
      { text: '实战经验', link: '/experience/README' },
      { text: '兵器谱', link: '/tools/Readme' }
    ],

    sidebar: {
      '/experience/': [
        {
          text: 'SRC 挖洞秘诀',
          items: [
            { text: '简介', link: '/experience/README' },
            { text: '403页面越权', link: '/experience/403页面/403-bypass' },
            { text: 'URL验证与注入', link: '/experience/URL注入/url-injection' },
            { text: 'Web服务器漏洞', link: '/experience/Web服务器/web-server-misconfig' },
            { text: '敏感信息泄露', link: '/experience/敏感信息泄露/swagger-leak' },
            { text: '短信验证码逻辑', link: '/experience/短信验证码/sms-logic-flaw' },
            { text: '管理系统漏洞', link: '/experience/管理页面/unauth-admin' }
          ]
        }
      ],
      '/tools/': [
        {
          text: '高效自动化工具套件',
          items: [
            { text: '工具导读', link: '/tools/Readme' },
            { text: 'Interact.sh 详解', link: '/tools/带外测试平台/interactsh-intro' },
            { text: 'Interact.sh 实战', link: '/tools/带外测试平台/interactsh-usage' },
            { text: 'Nuclei 扫雷机器', link: '/tools/漏扫工具/nuclei-intro' },
            { text: 'Nuclei 模板构建', link: '/tools/漏扫工具/nuclei-templates' },
            { text: 'afrog 神器', link: '/tools/漏扫工具/afrog-intro' },
            { text: 'SQLMap 自动化注入', link: '/tools/漏洞利用/sqlmap-usage' },
            { text: '自动化漏洞发现流', link: '/tools/自动化漏洞发现/netlas-nuclei-auto' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/owl234/Awesome-SRC-experience' }
    ],
    search: {
      provider: 'local'
    }
  }
})
