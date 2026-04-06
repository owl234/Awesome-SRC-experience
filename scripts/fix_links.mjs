import fs from 'fs';
import path from 'path';

const mapping = {
  '403页面': '403-bypass',
  'URL注入': 'url-injection',
  'Web服务器': 'web-servers',
  '敏感信息泄露': 'info-leak',
  '短信验证码': 'sms-verification',
  '管理页面': 'admin-panels',
  '带外测试平台': 'oob-testing',
  '漏扫工具': 'vuln-scanners',
  '漏洞利用': 'exploit-tools',
  '自动化漏洞发现': 'auto-discovery'
};

function walk(dir) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      walk(fullPath);
    } else if (file.endsWith('.md')) {
      let content = fs.readFileSync(fullPath, 'utf-8');
      let changed = false;
      for (const [oldName, newName] of Object.entries(mapping)) {
        // Match both raw and URI encoded
        const encoded = encodeURIComponent(oldName);
        const regexRaw = new RegExp(oldName, 'g');
        const regexEncoded = new RegExp(encoded, 'g');
        
        if (regexRaw.test(content)) {
          content = content.replace(regexRaw, newName);
          changed = true;
        }
        if (regexEncoded.test(content)) {
          content = content.replace(regexEncoded, newName);
          changed = true;
        }
      }
      if (changed) {
        fs.writeFileSync(fullPath, content);
        console.log(`Fixed links in: ${fullPath}`);
      }
    }
  }
}

walk('docs');
