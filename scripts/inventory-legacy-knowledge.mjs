#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const projectRoot = process.cwd();
const legacyRoot = path.resolve(process.argv[2] || path.join(projectRoot, '..', 'h00die-gr3y.github.io'));
const outDir = path.join(projectRoot, 'migration');
const roots = ['_pages', '_posts'];
const keywordGroups = {
  'Exploit Development': ['metasploit', 'msfconsole', 'msfvenom', 'exploit development', 'payload'],
  'Web Applications': ['burp', 'web application', 'php', 'sql', 'xss', 'upload', 'deserial', 'command injection'],
  'Infrastructure': ['active directory', 'windows', 'linux', 'kerberos', 'ldap', 'smb', 'privilege escalation'],
  'IoT & Embedded': ['firmware', 'router', 'iot', 'embedded', 'uart', 'ghidra', 'binwalk'],
  'Tools & Techniques': ['nmap', 'nuclei', 'shodan', 'wireshark', 'cheat sheet', 'cheatsheet', 'notes'],
};

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const p = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(p) : [p];
  });
}
function frontmatter(text) {
  if (!text.startsWith('---')) return {};
  const end = text.indexOf('\n---', 3);
  if (end < 0) return {};
  const block = text.slice(3, end).trim();
  const data = {};
  for (const line of block.split(/\r?\n/)) {
    const m = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (m) data[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
  }
  return data;
}
function classify(text) {
  const lower = text.toLowerCase();
  return Object.entries(keywordGroups)
    .map(([category, keywords]) => ({ category, score: keywords.filter((k) => lower.includes(k)).length }))
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score);
}

if (!fs.existsSync(legacyRoot)) {
  console.error(`Legacy repository not found: ${legacyRoot}`);
  console.error('Usage: node scripts/inventory-legacy-knowledge.mjs /path/to/h00die-gr3y.github.io');
  process.exit(1);
}

const files = roots.flatMap((r) => walk(path.join(legacyRoot, r)))
  .filter((f) => /\.(md|markdown|html?)$/i.test(f));
const records = files.map((file) => {
  const text = fs.readFileSync(file, 'utf8');
  const fm = frontmatter(text);
  const rel = path.relative(legacyRoot, file);
  const classes = classify(`${rel}\n${JSON.stringify(fm)}\n${text}`);
  return {
    path: rel,
    title: fm.title || path.basename(file),
    categories: fm.categories || fm.category || '',
    permalink: fm.permalink || '',
    suggestedCategory: classes[0]?.category || 'Unclassified',
    score: classes[0]?.score || 0,
    decision: 'REVIEW',
  };
}).sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'legacy-knowledge-inventory.json'), JSON.stringify(records, null, 2));
const lines = [
  '# Legacy Knowledge Inventory', '',
  `Source: \`${legacyRoot}\``, '',
  '> Suggested categories are keyword-assisted only. Every entry remains REVIEW until manually assessed as Keep, Rewrite, Merge or Archive.', '',
  '| Decision | Suggested area | Title | Legacy path |',
  '|---|---|---|---|',
  ...records.map((r) => `| ${r.decision} | ${r.suggestedCategory} | ${String(r.title).replace(/\|/g, '\\|')} | \`${r.path}\` |`),
  '',
  `Total candidate pages/posts scanned: ${records.length}`,
];
fs.writeFileSync(path.join(outDir, 'legacy-knowledge-inventory.md'), lines.join('\n'));
console.log(`Scanned ${records.length} legacy pages/posts.`);
console.log(`Wrote ${path.join(outDir, 'legacy-knowledge-inventory.md')}`);
