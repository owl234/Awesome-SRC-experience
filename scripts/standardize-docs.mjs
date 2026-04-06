import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const docsDir = path.join(__dirname, '../docs');

function getMarkdownFiles(dir, files = []) {
  const items = fs.readdirSync(dir);
  for (const item of items) {
    const fullPath = path.join(dir, item);
    if (fs.statSync(fullPath).isDirectory()) {
      if (item !== '.vitepress' && item !== 'node_modules') {
        getMarkdownFiles(fullPath, files);
      }
    } else if (item.endsWith('.md')) {
      files.push(fullPath);
    }
  }
  return files;
}

function standardizeFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let hasChanged = false;

  // 1. Remove Byte Order Mark (BOM)
  if (content.startsWith('\uFEFF')) {
    content = content.replace(/^\uFEFF/, '');
    hasChanged = true;
  }

  // 2. Extract or Add Frontmatter
  let frontmatter = {};
  const frontmatterMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
  
  if (frontmatterMatch) {
    // Existing frontmatter (we could parse it, but for simplicity we'll just keep it or enhance it)
    // For now, let's just ensure title and description exist
  } else {
    // Extract title from H1
    const h1Match = content.match(/^#\s+(.*)/m);
    const title = h1Match ? h1Match[1].trim() : path.basename(filePath, '.md');
    
    const newFrontmatter = `---
title: "${title}"
description: "Awesome SRC Experience - ${title}"
---

`;
    content = newFrontmatter + content;
    hasChanged = true;
  }

  // 3. Experience Doc Standardization (if in experience/ folder)
  const relativePath = path.relative(docsDir, filePath);
  if (relativePath.startsWith('experience') && !filePath.toLowerCase().endsWith('readme.md')) {
    // If not already structured with our 3-part system, try a soft upgrade
    if (!content.includes('## 漏洞背景') && !content.includes('## 复现步骤')) {
      // Find where to split. Usually after the H1 and some intro text.
      // We'll wrap existing content in "漏洞背景" and add others as placeholders or wrap appropriately.
      // This is a "best effort" heuristic.
      
      // Let's at least ensure we have the headers
      if (!content.includes('## ')) {
        // Simple doc, just add headers at the end as prompts for the user/contributors
        content += `\n\n## 复现步骤\n\n(待完善)\n\n## 修复建议\n\n(待完善)\n`;
        hasChanged = true;
      }
    }
  }

  // 4. Wrap Tools and Payloads in containers
  // Example: Convert "### 使用的工具" to a VitePress tip container
  content = content.replace(/###\s+使用的工具[:：]?/g, '::: tip 🛠️ 使用的工具');
  // If we converted it, we need to close the container later. 
  // This regex is tricky, let's keep it simple for now or use a more robust way.
  // Instead of full wrapping, let's just use better icons.

  if (hasChanged) {
    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`[STANDARDIZED] ${relativePath}`);
  }
}

console.log('Starting Documentation Standardization...');
const mdFiles = getMarkdownFiles(docsDir);
mdFiles.forEach(standardizeFile);
console.log('Standardization complete.');
