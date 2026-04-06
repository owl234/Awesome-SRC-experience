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
    const folders = fs.readdirSync(fullRoot)
    const subGroups = []

    for (const folder of folders) {
      if (folder === '.DS_Store' || folder.endsWith('.md') || folder === 'img' || folder === 'public') continue
      
      const folderPath = path.join(fullRoot, folder)
      if (fs.statSync(folderPath).isDirectory()) {
        const files = fs.readdirSync(folderPath)
        const items = []
        let groupTitle = folder // Fallback
        
        // Try to get group title from folder's README.md
        const folderReadme = files.find(f => f.toLowerCase() === 'readme.md')
        if (folderReadme) {
          const readmePath = path.join(folderPath, folderReadme)
          const readmeContent = fs.readFileSync(readmePath, 'utf-8').replace(/^\uFEFF/, '')
          const fmMatch = readmeContent.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/)
          if (fmMatch) {
            const titleMatch = fmMatch[1].match(/title:\s*["']?(.*?)["']?$/m)
            if (titleMatch) groupTitle = titleMatch[1].trim()
          }
          if (groupTitle === folder) {
            const h1Match = readmeContent.match(/^#\s+(.*)/m)
            if (h1Match) groupTitle = h1Match[1].trim()
          }
        }

        for (const file of files) {
          if (file.endsWith('.md') && file.toLowerCase() !== 'readme.md') {
            const filePath = path.join(folderPath, file)
            const content = fs.readFileSync(filePath, 'utf-8').replace(/^\uFEFF/, '') // Fix BOM
            
            // 1. Try to get title from frontmatter
            const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/)
            let title = ''
            if (fmMatch) {
              const titleMatch = fmMatch[1].match(/title:\s*["']?(.*?)["']?$/m)
              if (titleMatch) title = titleMatch[1].trim()
            }
            
            // 2. Fallback to H1
            if (!title) {
              const h1Match = content.match(/^#\s+(.*)/m)
              title = h1Match ? h1Match[1].trim() : file.replace('.md', '')
            }

            items.push({
              text: title,
              link: `/${baseDir}/${folder}/${file.replace('.md', '')}`
            })
          }
        }
        
        if (items.length > 0) {
          subGroups.push({
            text: groupTitle,
            collapsed: false,
            items: items
          })
        }
      }
    }

    // Sort subGroups alphabetically by title (text property)
    subGroups.sort((a, b) => a.text.localeCompare(b.text, 'zh'))
    categoryGroups.push(...subGroups)
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
    logo: '/img/hero.png',
    nav: [
      { text: '首页', link: '/' },
      { text: '实战经验', link: '/experience/README' },
      { text: '兵器谱', link: '/tools/Readme' }
    ],

    sidebar: {
      '/experience/': generateSidebar('experience', 'SRC 攻防实战'),
      '/tools/': generateSidebar('tools', '自动化兵器库')
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/owl234/Awesome-SRC-experience' }
    ],

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
