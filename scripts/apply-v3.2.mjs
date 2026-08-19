#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const root = process.cwd();
const changed = [];

function file(rel) {
  return path.join(root, rel);
}

function read(rel) {
  const target = file(rel);
  if (!fs.existsSync(target)) throw new Error(`Missing expected file: ${rel}`);
  return fs.readFileSync(target, 'utf8').replace(/\r\n/g, '\n');
}

function write(rel, text) {
  fs.writeFileSync(file(rel), text, 'utf8');
  changed.push(rel);
}

function replaceOnce(text, before, after, rel, label) {
  if (text.includes(after)) return text;
  const index = text.indexOf(before);
  if (index === -1) throw new Error(`${rel}: could not find expected ${label}`);
  return text.slice(0, index) + after + text.slice(index + before.length);
}

function update(rel, transform) {
  const before = read(rel);
  const after = transform(before);
  if (before !== after) write(rel, after);
}

const articleRel = 'src/content/research/cve-2026-53804.md';
const article = read(articleRel);
if (!article.includes('provenance: site-native')) throw new Error(`${articleRel}: missing site-native provenance.`);
if (!article.includes('researchType: original-research')) throw new Error(`${articleRel}: must be Original Research.`);
if (!article.includes('advisories: []')) throw new Error(`${articleRel}: disclosure advisory list must remain empty.`);
if (/security\/advisories/i.test(article)) throw new Error(`${articleRel}: contains a researcher-advisory reference.`);

// 1. Allow a published disclosure panel to show status/date/finder credit even
//    when the Research article intentionally has no advisory record.
update('src/components/DisclosurePanel.astro', (text) => {
  text = replaceOnce(
    text,
    '{disclosure && disclosure.advisories?.length > 0 && (\n',
    '{disclosure && (\n',
    'src/components/DisclosurePanel.astro',
    'disclosure panel visibility condition',
  );

  const before = `    <ul class="meta-links implementation-links">\n      {disclosure.advisories.map((advisory) => (\n        <li>\n          <div class="implementation-name">\n            {advisory.id ?? advisory.label}\n            <span class="tool-kind">[{advisoryTypeLabels[advisory.type] ?? advisory.type}]</span>\n          </div>\n          <div class="implementation-actions">\n            <a href={advisory.url} target="_blank" rel="noopener noreferrer">\n              {advisory.label} ↗<span class="sr-only"> (opens in a new tab)</span>\n            </a>\n          </div>\n          {advisory.published && <div class="implementation-name">Published {advisory.published}</div>}\n        </li>\n      ))}\n    </ul>\n`;
  const after = `    {(disclosure.advisories?.length ?? 0) > 0 && (\n      <ul class="meta-links implementation-links">\n        {disclosure.advisories.map((advisory) => (\n          <li>\n            <div class="implementation-name">\n              {advisory.id ?? advisory.label}\n              <span class="tool-kind">[{advisoryTypeLabels[advisory.type] ?? advisory.type}]</span>\n            </div>\n            <div class="implementation-actions">\n              <a href={advisory.url} target="_blank" rel="noopener noreferrer">\n                {advisory.label} ↗<span class="sr-only"> (opens in a new tab)</span>\n              </a>\n            </div>\n            {advisory.published && <div class="implementation-name">Published {advisory.published}</div>}\n          </li>\n        ))}\n      </ul>\n    )}\n`;
  return replaceOnce(text, before, after, 'src/components/DisclosurePanel.astro', 'conditional advisory list');
});

// 2. Release QA: v3.2 has a 64-entry minimum and locks the new canonical
//    site-native CVE publication to the intended disclosure model.
update('scripts/qa-site.mjs', (text) => {
  text = replaceOnce(
    text,
    'if (researchFiles.length < 63) failures.push(`Expected at least 63 research entries, found ${researchFiles.length}.`);\n',
    'if (researchFiles.length < 64) failures.push(`Expected at least 64 research entries, found ${researchFiles.length}.`);\n',
    'scripts/qa-site.mjs',
    'v3.2 research minimum',
  );

  if (!text.includes("const canonicalNativeCve = 'cve-2026-53804.md';")) {
    const block = `// v3.2 canonical site-native publication.\nconst canonicalNativeCve = 'cve-2026-53804.md';\nconst canonicalNativeCveFile = researchFiles.find((candidate) => path.basename(candidate) === canonicalNativeCve);\nif (!canonicalNativeCveFile) {\n  failures.push(\`Missing canonical Research publication: \${canonicalNativeCve}.\`);\n} else {\n  const canonicalText = read(canonicalNativeCveFile);\n  const canonicalFm = frontmatter(canonicalText);\n  if (!/^cve:\\s*CVE-2026-53804\\s*$/m.test(canonicalFm)) failures.push(\`\${rel(canonicalNativeCveFile)} is missing CVE-2026-53804 metadata.\`);\n  if (!/^researchType:\\s*original-research\\s*$/m.test(canonicalFm)) failures.push(\`\${rel(canonicalNativeCveFile)} must be Original Research.\`);\n  if (!/^ {2}provenance:\\s*site-native\\s*$/m.test(canonicalFm)) failures.push(\`\${rel(canonicalNativeCveFile)} must use site-native provenance.\`);\n  if (!/^ {2}url:\\s*https:\\/\\/h00die-gr3y\\.github\\.io\\/research\\/cve-2026-53804\\/\\s*$/m.test(canonicalFm)) failures.push(\`\${rel(canonicalNativeCveFile)} has the wrong canonical source URL.\`);\n  if (!/^ {2}status:\\s*published\\s*$/m.test(canonicalFm)) failures.push(\`\${rel(canonicalNativeCveFile)} must be published.\`);\n  if (!/^ {2}credit:\\s*h00die-gr3y — Finder\\s*$/m.test(canonicalFm)) failures.push(\`\${rel(canonicalNativeCveFile)} is missing finder credit.\`);\n  if (!/^ {2}advisories:\\s*\\[\\]\\s*$/m.test(canonicalFm)) failures.push(\`\${rel(canonicalNativeCveFile)} must not create an advisory record.\`);\n  if (/security\\/advisories/i.test(canonicalText)) failures.push(\`\${rel(canonicalNativeCveFile)} contains a researcher-advisory reference.\`);\n  if (!canonicalText.includes('Kernel/System/Crypt/PGP.pm')) failures.push(\`\${rel(canonicalNativeCveFile)} is missing the PGP.pm root-cause path.\`);\n  if (!canonicalText.includes('PGP::Bin') || !canonicalText.includes('PGP::Options')) failures.push(\`\${rel(canonicalNativeCveFile)} is missing the affected PGP settings.\`);\n}\n\nconst disclosurePanelV32 = read(path.join(src, 'components', 'DisclosurePanel.astro'));\nif (disclosurePanelV32.includes('disclosure && disclosure.advisories?.length > 0')) {\n  failures.push('DisclosurePanel still hides published disclosure metadata when there are no advisory records.');\n}\n\n`;
    text = replaceOnce(
      text,
      '// Every rendered main region must expose the skip-link target.\n',
      `${block}// Every rendered main region must expose the skip-link target.\n`,
      'scripts/qa-site.mjs',
      'v3.2 canonical publication QA block',
    );
  }

  if (!text.includes('Canonical native CVE publication: CVE-2026-53804')) {
    text = replaceOnce(
      text,
      'notes.push(`Structured researcher advisories: ${researcherAdvisoryCount}`);\n',
      'notes.push(`Structured researcher advisories: ${researcherAdvisoryCount}`);\nnotes.push(`Canonical native CVE publication: CVE-2026-53804`);\n',
      'scripts/qa-site.mjs',
      'v3.2 QA note',
    );
  }

  return text;
});

// 3. Document the no-advisory first-class Research pattern without changing
//    the historical advisory records already preserved by v3.1.
update('DISCLOSURE-ADVISORIES.md', (text) => {
  text = text.replace('# Disclosure and advisory model — v3.1.1\n', '# Disclosure and advisory model — v3.2\n');
  if (!text.includes('## First-class Research without an advisory record')) {
    text += `\n## First-class Research without an advisory record\n\nCVE-2026-53804 is published as a first-class, site-native **Original Research** article at \`/research/cve-2026-53804/\`. The Research page is the canonical technical publication.\n\nIts structured \`disclosure\` object uses \`status: published\` and finder credit while leaving \`advisories: []\`. This intentionally keeps the publication out of the Published Advisories portfolio while preserving disclosure metadata on the Research detail page.\n\nThe Research, CVE and Exploit Development indexes derive their totals from the content collection and therefore include the new entry automatically. The preserved AttackerKB baseline remains 63 entries.\n`;
  }
  return text;
});

console.log('h00die-gr3y v3.2 canonical CVE research publication');
console.log('--------------------------------------------------');
if (changed.length === 0) {
  console.log('No changes needed; v3.2 support appears to be applied already.');
} else {
  for (const rel of changed) console.log(`UPDATED ${rel}`);
  console.log(`\nApplied ${changed.length} supporting source updates.`);
}
