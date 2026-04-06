import fs from 'fs';
import path from 'path';

function generateFlatSidebar(baseDir) {
  const fullRoot = path.join(process.cwd(), 'docs', baseDir)
  const items = []
  
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
  return items;
}

console.log(generateFlatSidebar('tools'));
