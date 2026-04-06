import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const docsDir = path.join(__dirname, '../docs');

/**
 * Recursively find all markdown files
 */
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

/**
 * Fix a single markdown file to be Vue-safe
 */
function fixMarkdownFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let hasChanged = false;

  // 1. Remove any previously added <div v-pre> wrappers (we want a clean slate)
  if (content.includes('<div v-pre>')) {
    content = content.replace(/<div v-pre>\r?\n?/g, '');
    content = content.replace(/\r?\n?<\/div>\r?\n?$/g, '');
    hasChanged = true;
  }

  // 2. Escape pseudo-HTML tags that are NOT inside code blocks
  // We split by code blocks to avoid messing with already protected content
  const segments = content.split(/(```[\s\S]*?```)/g);
  const processedSegments = segments.map((segment) => {
    if (segment.startsWith('```')) {
      return segment; // Keep code blocks as is
    }
    
    // Find <TagLike> patterns where Tag starts with a letter and doesn't belong to a known safe tag
    // We escape < to &lt; and > to &gt;
    const newSegment = segment.replace(/<([a-zA-Z][^>\s]*?)>/g, (match, tagName) => {
      // List of HTML tags we might actually WANT to allow in Markdown (rare in this repo)
      const allowedTags = ['br', 'img', 'hr', 'a', 'span', 'div', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'style', 'code', 'blockquote', 'section', 'article']; 
      if (allowedTags.includes(tagName.toLowerCase())) {
        return match;
      }
      hasChanged = true;
      return `&lt;${tagName}&gt;`;
    });
    
    return newSegment;
  });

  if (hasChanged) {
    fs.writeFileSync(filePath, processedSegments.join(''), 'utf8');
    console.log(`[FIXED] ${path.relative(docsDir, filePath)}`);
  }
}

console.log('Starting Markdown build-safety scan...');
const mdFiles = getMarkdownFiles(docsDir);
console.log(`Found ${mdFiles.length} markdown files.`);
mdFiles.forEach(fixMarkdownFile);
console.log('Markdown scan complete.');
