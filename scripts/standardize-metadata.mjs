import fs from 'fs';
import path from 'path';

const baseDir = 'docs/experience';

function walk(dir) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      walk(fullPath);
    } else if (file.endsWith('.md') && file.toLowerCase() !== 'readme.md') {
      updateFrontmatter(fullPath);
    }
  }
}

function updateFrontmatter(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const relative = path.relative(baseDir, filePath);
  const parts = relative.split(path.sep);
  const targetType = parts[0]; // e.g., 'web', 'iot'

  const fmRegex = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/;
  const match = content.match(fmRegex);

  if (match) {
    let fm = match[1];
    
    // Update target_type
    if (fm.includes('target_type:')) {
      fm = fm.replace(/target_type:\s*["']?.*?["']?$/m, `target_type: "${targetType}"`);
    } else {
      fm += `\ntarget_type: "${targetType}"`;
    }

    // Default values if missing
    if (!fm.includes('author:')) fm += `\nauthor: "Awesome-SRC Contributor"`;
    if (!fm.includes('difficulty:')) fm += `\ndifficulty: "Medium"`;

    const newContent = content.replace(fmRegex, `---\n${fm.trim()}\n---\n`);
    fs.writeFileSync(filePath, newContent);
    console.log(`Updated: ${filePath} (Target: ${targetType})`);
  } else {
    // No frontmatter, create it
    const newContent = `---\ntitle: "${path.basename(filePath, '.md')}"\ntarget_type: "${targetType}"\nauthor: "Awesome-SRC Contributor"\ndifficulty: "Medium"\n---\n\n${content}`;
    fs.writeFileSync(filePath, newContent);
    console.log(`Created FM: ${filePath} (Target: ${targetType})`);
  }
}

walk(baseDir);
console.log("Metadata standardization complete.");
