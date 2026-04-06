import { defineConfig } from 'vitepress'
import fs from 'fs'
import path from 'path'

// 自动生成侧边栏的函数
function generateFlatSidebar(baseDir, rootTitle) {
  const fullRoot = path.join(__dirname, '../', baseDir)
  const items = [{ text: '简介', link: `/${baseDir}/README` }]
  
  if (fs.existsSync(fullRoot)) {
    const folders = fs.readdirSync(fullRoot)
    for (const item of folders) {
      if (item === '.DS_Store' || item.endsWith('.md')) continue
      
      const categoryPath = path.join(fullRoot, item)
      if (fs.statSync(categoryPath).isDirectory()) {
        const files = fs.readdirSync(categoryPath)
        for (const file of files) {
          if (file.endsWith('.md') && file.toLowerCase() !== 'readme.md') {
            const filePath = path.join(categoryPath, file)
            const content = fs.readFileSync(filePath, 'utf-8')
            const titleMatch = content.replace(/\uFEFF/g, '').match(/^#\s+(.*)/m)
            const text = titleMatch ? titleMatch[1].trim() : file.replace('.md', '')
            
            items.push({
              text: text,
              link: `/${baseDir}/${item}/${file.replace('.md', '')}`
            })
          }
        }
      }
    }
  }
  
  return [
    {
      text: rootTitle,
      items: items
    }
  ]
}

export default defineConfig({
  title: "Awesome SRC Experience",
  description: "企业级 SRC 漏洞挖掘实战经验与自动化利器集合",
  base: '/Awesome-SRC-experience/',
  themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
      { text: '实战经验', link: '/experience/README' },
      { text: '兵器谱', link: '/tools/Readme' }
    ],

    sidebar: {
      '/experience/': generateFlatSidebar('experience', 'SRC 挖洞秘诀'),
      '/tools/': generateFlatSidebar('tools', '高效自动化工具套件')
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/owl234/Awesome-SRC-experience' }
    ],
    search: {
      provider: 'local'
    }
  }
})
