import { defineConfig } from 'vitepress'
import fs from 'fs'
import path from 'path'

// Robust sidebar generation function
function generateSidebar(baseDir, rootTitle) {
  const fullRoot = path.join(process.cwd(), 'docs', baseDir)
  const categoryGroups = []

  // Add the "Overview" page first
  const rootReadme = path.join(fullRoot, 'README.md')
  const rootReadmeAlt = path.join(fullRoot, 'Readme.md')
  if (fs.existsSync(rootReadme) || fs.existsSync(rootReadmeAlt)) {
    categoryGroups.push({
      text: rootTitle,
      items: [{ text: '💡 概览与简介', link: `/${baseDir}/${fs.existsSync(rootReadme) ? 'README' : 'Readme'}` }]
    })
  }

  if (fs.existsSync(fullRoot)) {
    // 递归文件树扫描引擎
    function walkDirectory(currentDir, routePrefix, depth = 0) {
      const items = []
      const entries = fs.readdirSync(currentDir, { withFileTypes: true })
      
      // 排序规则：文件夹优先，然后按字母排序
      entries.sort((a, b) => {
        if (a.isDirectory() && !b.isDirectory()) return -1
        if (!a.isDirectory() && b.isDirectory()) return 1
        return a.name.localeCompare(b.name, 'zh')
      })

      for (const entry of entries) {
        const entryName = entry.name
        // 自动忽略隐藏文件、静态资源与系统目录
        if (entryName.startsWith('.') || entryName === 'img' || entryName === 'public' || entryName === 'node_modules') {
          continue
        }

        const fullPath = path.join(currentDir, entryName)

        if (entry.isDirectory()) {
          const subItems = walkDirectory(fullPath, `${routePrefix}/${entryName}`, depth + 1)
          if (subItems.length > 0) {
            const icon = depth === 0 ? '🛡️' : '📂'
            
            // 目录名中英文化映射表
            const dict = {
              'web': 'Web 攻防',
              'iot': '物联网安全',
              'infrastructure': '基础设施',
              'cloud': '云原生架构',
              'auto-discovery': '自动化资产发现',
              'exploit-tools': '漏洞利用组件',
              'oob-testing': '带外探测 (OOB)',
              'vuln-scanners': '综合漏洞扫描'
            }
            const rawName = entryName.toLowerCase()
            // 仅对顶级目录生效中文映射，子目录保留英文首字母大写
            const displayName = (depth === 0 && dict[rawName])
              ? dict[rawName]
              : (entryName.charAt(0).toUpperCase() + entryName.slice(1))

            items.push({
              text: `${icon} ${displayName}`,
              collapsed: false,
              items: subItems
            })
          }
        } else if (entry.isFile() && entryName.endsWith('.md') && entryName.toLowerCase() !== 'readme.md') {
          // 安全的标题提取逻辑
          const content = fs.readFileSync(fullPath, 'utf-8').replace(/^\uFEFF/, '')
          let title = ''
          
          const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/)
          if (fmMatch) {
            const titleMatch = fmMatch[1].match(/title:\s*["']?(.*?)["']?$/m)
            if (titleMatch) title = titleMatch[1].trim()
          }
          if (!title) {
            const h1Match = content.match(/^#\s+(.*)/m)
            title = h1Match ? h1Match[1].trim() : entryName.replace('.md', '')
          }

          items.push({
            text: title,
            link: `${routePrefix}/${entryName.replace('.md', '')}`
          })
        }
      }
      return items
    }

    const tree = walkDirectory(fullRoot, `/${baseDir}`)
    categoryGroups.push(...tree)
  }
  
  return categoryGroups
}

export default defineConfig({
  title: "Awesome SRC Experience",
  description: "企业级 SRC 漏洞挖掘实战经验与自动化利器集合",
  base: '/Awesome-SRC-experience/',
  head: [
    ['link', { rel: 'icon', href: '/favicon.ico' }],
    ['meta', { name: 'viewport', content: 'width=device-width,initial-scale=1' }],
    ['meta', { property: 'og:title', content: 'Awesome SRC Experience' }],
    ['meta', { property: 'og:description', content: '让漏洞挖掘不再是“盲人摸象” - 高性能安全经验库' }],
    ['meta', { name: 'theme-color', content: '#7d4cdb' }]
  ],

  themeConfig: {
    nav: [
      { text: '首页', link: '/' },
      { text: '实战经验', link: '/experience/README' },
      { text: '兵器谱', link: '/tools/Readme' },
      { text: '✍️ 参与共建', link: '/contribute' }
    ],

    sidebar: {
      '/experience/': generateSidebar('experience', 'SRC 攻防实战'),
      '/tools/': generateSidebar('tools', '自动化兵器库')
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/owl234/Awesome-SRC-experience' }
    ],

    editLink: {
      pattern: 'https://github.com/owl234/Awesome-SRC-experience/edit/main/docs/:path',
      text: '📝 在 GitHub 上编辑此页'
    },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026-present Awesome-SRC-Experience'
    },

    search: {
      provider: 'local',
      options: {
        locales: {
          zh: {
            translations: {
              button: {
                buttonText: '搜索文档',
                buttonAriaLabel: '搜索文档'
              },
              modal: {
                noResultsText: '无法找到相关结果',
                resetButtonTitle: '清除查询条件',
                footer: {
                  selectText: '选择',
                  navigateText: '切换'
                }
              }
            }
          }
        }
      }
    }
  }
})
