import fs from 'fs';

function fixFile(file) {
  let content = fs.readFileSync(file, 'utf8');
  
  // Remove <div v-pre> and </div>
  content = content.replace('<div v-pre>\n', '');
  content = content.replace('<div v-pre>\r\n', '');
  content = content.replace('\n</div>\n', '\n');
  content = content.replace('\n</div>\r\n', '\n');
  content = content.replace('\r\n</div>\r\n', '\r\n');
  content = content.replace('</div>\n', '\n');
  content = content.replace('</div>\r\n', '\r\n');
  
  // Escape specific naked tags that are causing Vue issues (replace globally)
  content = content.replace(/<input>/g, '&lt;input&gt;');
  content = content.replace(/<button>/g, '&lt;button&gt;');
  content = content.replace(/<logical_operator>/g, '&lt;logical_operator&gt;');
  content = content.replace(/<int>/g, '&lt;int&gt;');
  content = content.replace(/\"<>/g, '\"&lt;&gt;'); 

  fs.writeFileSync(file, content, 'utf8');
  console.log('Fixed', file);
}

fixFile('docs/tools/漏扫工具/Nuclei：使用Nuclei查找漏洞的终极指南.md');
fixFile('docs/tools/漏洞利用/Metasploit：Metasploit 入门.md');
