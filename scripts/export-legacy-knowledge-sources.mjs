#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const projectRoot = process.cwd();
const legacyRoot = path.resolve(process.argv[2] || path.join(projectRoot, '..', 'h00die-gr3y.github.io'));
const outDir = path.join(projectRoot, 'migration');

// These are the legacy sources selected for manual Knowledge Base migration.
// Other inventory entries are either redirects, archive-only pages, or already
// represented by migrated Research content.
const selectedSources = [
  '_pages/ad-domain-attack.md',
  '_pages/tips-and-tricks.md',
  '_pages/module-development.md',
  '_posts/2024-08-26-howto-uart-shell.md',
  '_pages/iot-uart-shell.md',
  '_pages/references.md',
  '_pages/log4shell.md',
];

function splitFrontmatter(text) {
  const normalized = text.replace(/\r\n/g, '\n');
  if (!normalized.startsWith('---\n')) {
    return { frontmatterRaw: '', body: normalized };
  }

  const end = normalized.indexOf('\n---\n', 4);
  if (end === -1) {
    return { frontmatterRaw: '', body: normalized };
  }

  return {
    frontmatterRaw: normalized.slice(4, end),
    body: normalized.slice(end + 5),
  };
}

function parseSimpleFrontmatter(raw) {
  const data = {};
  for (const line of raw.split('\n')) {
    const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!match) continue;
    data[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
  return data;
}

if (!fs.existsSync(legacyRoot)) {
  console.error(`Legacy repository not found: ${legacyRoot}`);
  console.error('Usage: node scripts/export-legacy-knowledge-sources.mjs /path/to/h00die-gr3y.github.io');
  process.exit(1);
}

const records = [];
const missing = [];

for (const relativePath of selectedSources) {
  const absolutePath = path.join(legacyRoot, relativePath);
  if (!fs.existsSync(absolutePath)) {
    missing.push(relativePath);
    continue;
  }

  const source = fs.readFileSync(absolutePath, 'utf8').replace(/\r\n/g, '\n');
  const { frontmatterRaw, body } = splitFrontmatter(source);
  const frontmatter = parseSimpleFrontmatter(frontmatterRaw);

  records.push({
    path: relativePath,
    title: frontmatter.title || path.basename(relativePath),
    permalink: frontmatter.permalink || '',
    frontmatter,
    frontmatterRaw,
    body,
    source,
  });
}

if (missing.length > 0) {
  console.error('The following selected legacy files were not found:');
  for (const item of missing) console.error(`  - ${item}`);
  process.exit(2);
}

fs.mkdirSync(outDir, { recursive: true });

const jsonPath = path.join(outDir, 'legacy-knowledge-source-export.json');
fs.writeFileSync(jsonPath, `${JSON.stringify({
  sourceRoot: legacyRoot,
  exportedAt: new Date().toISOString(),
  files: records,
}, null, 2)}\n`);

const mdLines = [
  '# Legacy Knowledge Source Export',
  '',
  `Source: \`${legacyRoot}\``,
  '',
  `Selected source files exported: **${records.length}**`,
  '',
  '> This export preserves the original legacy source text for editorial migration. No source files are modified.',
  '',
  '## Included sources',
  '',
  ...records.map((record) => `- \`${record.path}\` — ${record.title}`),
  '',
];

for (const record of records) {
  mdLines.push(
    '---',
    '',
    `## ${record.path}`,
    '',
    `**Title:** ${record.title}`,
    '',
    record.permalink ? `**Legacy permalink:** \`${record.permalink}\`` : '**Legacy permalink:** not explicitly defined',
    '',
    `<!-- BEGIN LEGACY SOURCE: ${record.path} -->`,
    '',
    record.source.trimEnd(),
    '',
    `<!-- END LEGACY SOURCE: ${record.path} -->`,
    '',
  );
}

const mdPath = path.join(outDir, 'legacy-knowledge-source-export.md');
fs.writeFileSync(mdPath, `${mdLines.join('\n')}\n`);

console.log(`Exported ${records.length} legacy Knowledge Base source files.`);
console.log(`Wrote ${mdPath}`);
console.log(`Wrote ${jsonPath}`);
