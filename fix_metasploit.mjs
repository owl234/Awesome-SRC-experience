import fs from 'fs';

const file = 'docs/tools/漏洞利用/Metasploit：Metasploit 入门.md';
let content = fs.readFileSync(file, 'utf8');

// The goal is to safely escape all `<` characters that act as placeholders like <Attacker IP> or <payload>
// Regex captures < (followed by letters, underscores, or spaces, and optionally other chars) >
// But it's easier to just replace all `<` and `>` directly if they are followed by an english letter or an underscore.
// We only want to escape those that Vue mistakes for HTML elements.
// Vue mistakes any word character following a `<` as a tag name. Example: `<payload>`, `<format>`, `<Attacker IP>`

content = content.replace(/<([a-zA-Z]+)([^>]*)>/g, '&lt;$1$2&gt;');

fs.writeFileSync(file, content, 'utf8');
console.log('Metasploit file fixed by replacing pseudo-tags with HTML entities.');
