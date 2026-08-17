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

// 1. Research schema: add optional HGR identifier and structured disclosure metadata.
update('src/content.config.ts', (text) => {
  const marker = "    disclosureDate: z.string().nullable(),\n";
  const replacement = `${marker}    researchId: z.string().regex(/^HGR-\\d{4}-\\d{3}$/).nullable().optional(),\n    disclosure: z.object({\n      status: z.enum(['embargoed', 'coordinated', 'published']),\n      credit: z.string().nullable().optional(),\n      reported: z.string().nullable().optional(),\n      advisories: z.array(z.object({\n        type: z.enum(['researcher', 'vendor', 'github', 'other']),\n        label: z.string(),\n        id: z.string().nullable().optional(),\n        url: z.string(),\n        published: z.string().nullable().optional(),\n      })).default([]),\n    }).nullable().optional(),\n`;
  return replaceOnce(text, marker, replacement, 'src/content.config.ts', 'disclosureDate schema field');
});

// 2. Research detail layout: render the advisory state as first-class disclosure metadata.
update('src/layouts/ResearchLayout.astro', (text) => {
  text = replaceOnce(
    text,
    "import Footer from '../components/Footer.astro';\n",
    "import Footer from '../components/Footer.astro';\nimport DisclosurePanel from '../components/DisclosurePanel.astro';\n",
    'src/layouts/ResearchLayout.astro',
    'Footer import',
  );

  text = replaceOnce(
    text,
    "          {data.exploitDevelopment && <span class=\"research-output-label\">EXPLOIT DEVELOPMENT</span>}\n          {data.cve && <span class=\"research-cve\">{data.cve}</span>}\n",
    "          {data.exploitDevelopment && <span class=\"research-output-label\">EXPLOIT DEVELOPMENT</span>}\n          {(data.disclosure?.advisories?.length ?? 0) > 0 && <span class=\"research-output-label\">PUBLISHED ADVISORY</span>}\n          {data.cve && <span class=\"research-cve\">{data.cve}</span>}\n",
    'src/layouts/ResearchLayout.astro',
    'research hero labels',
  );

  text = text.replace("              {data.disclosureDate && <div><dt>Disclosure</dt><dd>{data.disclosureDate}</dd></div>}\n", '');

  text = replaceOnce(
    text,
    "          {relatedKnowledge.length > 0 && (\n",
    "          <DisclosurePanel data={data} />\n\n          {relatedKnowledge.length > 0 && (\n",
    'src/layouts/ResearchLayout.astro',
    'related knowledge panel',
  );

  return text;
});

// 3. Research index: expose the advisory portfolio without adding a main navigation item.
update('src/pages/research/index.astro', (text) => {
  return replaceOnce(
    text,
    "        <p>Original discoveries, independent technical analysis and practical exploit development preserved from the h00die-gr3y research archive.</p>\n",
    "        <p>Original discoveries, independent technical analysis and practical exploit development preserved from the h00die-gr3y research archive.</p>\n        <div class=\"hero-actions\">\n          <a class=\"button button-secondary\" href=\"/advisories/\">Published advisories <span>→</span></a>\n        </div>\n",
    'src/pages/research/index.astro',
    'research hero copy',
  );
});

// 4. About: make the disclosure portfolio part of the site model.
update('src/pages/about/index.astro', (text) => {
  text = replaceOnce(
    text,
    "          <p>This site is my working archive for that research. The <a href=\"/research/\">Research</a> section contains vulnerability-specific analysis, <a href=\"/exploits/\">Exploits</a> collects the exploit-development work, <a href=\"/articles/\">Articles</a> connects ideas across individual findings, and the <a href=\"/knowledge-base/\">Knowledge Base</a> keeps reusable techniques and lab notes in one place.</p>\n",
    "          <p>This site is my working archive for that research. The <a href=\"/research/\">Research</a> section contains vulnerability-specific analysis, <a href=\"/exploits/\">Exploits</a> collects the exploit-development work, <a href=\"/articles/\">Articles</a> connects ideas across individual findings, and the <a href=\"/knowledge-base/\">Knowledge Base</a> keeps reusable techniques and lab notes in one place. Published CVE, vendor and security-advisory records are collected under <a href=\"/advisories/\">Published advisories</a>.</p>\n",
    'src/pages/about/index.astro',
    'about disclosure paragraph',
  );

  text = replaceOnce(
    text,
    "          <a href=\"/articles/\"><span>Articles</span><strong>Long-form technical writing</strong><b>→</b></a>\n          <a href=\"https://github.com/h00die-gr3y\" target=\"_blank\" rel=\"noopener noreferrer\"><span>GitHub</span><strong>Code and public research work</strong><b>↗</b><span class=\"sr-only\"> (opens in a new tab)</span></a>\n",
    "          <a href=\"/articles/\"><span>Articles</span><strong>Long-form technical writing</strong><b>→</b></a>\n          <a href=\"/advisories/\"><span>Advisories</span><strong>Published disclosure records</strong><b>→</b></a>\n          <a href=\"https://github.com/h00die-gr3y\" target=\"_blank\" rel=\"noopener noreferrer\"><span>GitHub</span><strong>Code and public research work</strong><b>↗</b><span class=\"sr-only\"> (opens in a new tab)</span></a>\n",
    'src/pages/about/index.astro',
    'about links',
  );

  return text;
});

// 5. Footer: secondary navigation only; the main header remains unchanged.
update('src/components/Footer.astro', (text) => {
  return replaceOnce(
    text,
    "      <a href=\"/rss.xml\">RSS</a>\n      <a href=\"/disclaimer/\">Disclaimer</a>\n",
    "      <a href=\"/rss.xml\">RSS</a>\n      <a href=\"/advisories/\">Advisories</a>\n      <a href=\"/disclaimer/\">Disclaimer</a>\n",
    'src/components/Footer.astro',
    'footer metadata links',
  );
});

// 6. Sitemap: add the generated advisory portfolio and derive its last modification date.
update('src/pages/sitemap.xml.ts', (text) => {
  text = replaceOnce(
    text,
    "  const latestResearch = maxDate(research.map((entry) => entry.data.revised || entry.data.published));\n  const latestArticle = maxDate(articles.map((entry) => entry.data.revised || entry.data.published));\n",
    "  const latestResearch = maxDate(research.map((entry) => entry.data.revised || entry.data.published));\n  const latestAdvisory = maxDate(research.flatMap((entry) => entry.data.disclosure?.advisories.map((item) => item.published ?? '') ?? []));\n  const latestArticle = maxDate(articles.map((entry) => entry.data.revised || entry.data.published));\n",
    'src/pages/sitemap.xml.ts',
    'latest research dates',
  );

  text = replaceOnce(
    text,
    "    { path: '/research/', lastmod: latestResearch },\n    { path: '/cves/', lastmod: latestResearch },\n",
    "    { path: '/research/', lastmod: latestResearch },\n    { path: '/advisories/', lastmod: latestAdvisory || latestResearch },\n    { path: '/cves/', lastmod: latestResearch },\n",
    'src/pages/sitemap.xml.ts',
    'research sitemap entry',
  );

  return text;
});

function addDisclosureFrontmatter(text, rel, block) {
  if (text.includes('\ndisclosure:\n')) return text;
  const match = text.match(/disclosureDate: [^\n]+\n/);
  if (!match) throw new Error(`${rel}: missing disclosureDate frontmatter`);
  return text.replace(match[0], `${match[0]}${block}`);
}

// 7. Historical GHSA records: keep them attached to their existing original-research entries.
update('src/content/research/cve-2025-4653.md', (text) => {
  text = addDisclosureFrontmatter(text, 'src/content/research/cve-2025-4653.md', `researchId: null\ndisclosure:\n  status: published\n  credit: Finder\n  advisories:\n  - type: researcher\n    label: GitHub Security Advisory\n    id: GHSA-m4f8-9c8x-8f3f\n    url: https://github.com/h00die-gr3y/h00die-gr3y/security/advisories/GHSA-m4f8-9c8x-8f3f\n    published: '2025-06-17'\n  - type: vendor\n    label: Pandora vulnerability overview\n    url: https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/\n`);

  text = text.replace("- label: 'misc'\n  url: 'https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/'\n  type: 'misc'\n", '');
  text = text.replace("- [Security advisory GHSA-m4f8-9c8x-8f3f](https://github.com/h00die-gr3y/h00die-gr3y/security/advisories/GHSA-m4f8-9c8x-8f3f)\n", '');
  text = text.replace("- [Pandora vulnerability overview](https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/)\n", '');
  return text;
});

update('src/content/research/cve-2025-4678.md', (text) => {
  text = addDisclosureFrontmatter(text, 'src/content/research/cve-2025-4678.md', `researchId: null\ndisclosure:\n  status: published\n  credit: Finder\n  advisories:\n  - type: researcher\n    label: GitHub Security Advisory\n    id: GHSA-wcqx-vw37-9pv8\n    url: https://github.com/h00die-gr3y/h00die-gr3y/security/advisories/GHSA-wcqx-vw37-9pv8\n    published: '2025-08-12'\n  - type: vendor\n    label: Pandora vulnerability overview\n    url: https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/\n`);

  text = text.replace("- label: 'misc'\n  url: 'https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/'\n  type: 'misc'\n", '');
  text = text.replace("- [Security advisory GHSA-wcqx-vw37-9pv8](https://github.com/h00die-gr3y/h00die-gr3y/security/advisories/GHSA-wcqx-vw37-9pv8)\n", '');
  text = text.replace("- [Pandora vulnerability overview](https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/)\n", '');
  return text;
});

update('src/content/research/cve-2025-5946.md', (text) => {
  text = addDisclosureFrontmatter(text, 'src/content/research/cve-2025-5946.md', `researchId: null\ndisclosure:\n  status: published\n  credit: Finder\n  advisories:\n  - type: researcher\n    label: GitHub Security Advisory\n    id: GHSA-g6r8-jjf7-w7gh\n    url: https://github.com/h00die-gr3y/h00die-gr3y/security/advisories/GHSA-g6r8-jjf7-w7gh\n    published: '2025-11-02'\n  - type: vendor\n    label: Centreon security bulletin\n    url: https://thewatch.centreon.com/latest-security-bulletins-64/cve-2025-5946-centreon-web-all-versions-high-severity-5104\n`);

  text = text.replace("- label: 'advisory'\n  url: 'https://thewatch.centreon.com/latest-security-bulletins-64/cve-2025-5946-centreon-web-all-versions-high-severity-5104'\n  type: 'advisory'\n", '');
  text = text.replace("- [Centreon security bulletin](https://thewatch.centreon.com/latest-security-bulletins-64/cve-2025-5946-centreon-web-all-versions-high-severity-5104)\n", "- [Centreon release history](https://github.com/centreon/centreon/releases)\n");
  return text;
});

// 8. Release QA: lock the three historical researcher advisories to their Research records.
update('scripts/qa-site.mjs', (text) => {
  const block = [
    '',
    '// Disclosure/advisory integration: the three historical researcher GHSAs must remain attached',
    '// to their existing first-class Research entries, not duplicated as separate content.',
    'const expectedResearcherAdvisories = new Map([',
    "  ['cve-2025-4653.md', 'GHSA-m4f8-9c8x-8f3f'],",
    "  ['cve-2025-4678.md', 'GHSA-wcqx-vw37-9pv8'],",
    "  ['cve-2025-5946.md', 'GHSA-g6r8-jjf7-w7gh'],",
    ']);',
    'let researcherAdvisoryCount = 0;',
    'for (const [name, ghsa] of expectedResearcherAdvisories) {',
    '  const target = researchFiles.find((candidate) => path.basename(candidate) === name);',
    '  if (!target) {',
    '    failures.push(`Missing Research entry expected for ${ghsa}: ${name}.`);',
    '    continue;',
    '  }',
    '  const text = read(target);',
    '  if (!text.includes(`id: ${ghsa}`)) failures.push(`${rel(target)} is missing structured advisory ${ghsa}.`);',
    "  if (!text.includes('type: researcher')) failures.push(`${rel(target)} is missing researcher advisory classification.`);",
    "  const referencesBody = text.split('## References')[1]?.split('## ')[0] ?? '';",
    '  if (referencesBody.includes(ghsa)) failures.push(`${rel(target)} duplicates ${ghsa} in the body References section.`);',
    '  researcherAdvisoryCount += 1;',
    '}',
    '',
    "const advisoriesPage = path.join(src, 'pages', 'advisories', 'index.astro');",
    "if (!fs.existsSync(advisoriesPage)) failures.push('Missing /advisories/ page.');",
    "const sitemap = read(path.join(src, 'pages', 'sitemap.xml.ts'));",
    "if (!sitemap.includes(\"{ path: '/advisories/'\")) failures.push('Sitemap is missing /advisories/.');",
    '',
  ].join('\n');

  if (!text.includes('const expectedResearcherAdvisories = new Map([')) {
    text = replaceOnce(
      text,
      "// Check Markdown code fences are balanced.\n",
      `${block}\n// Check Markdown code fences are balanced.\n`,
      'scripts/qa-site.mjs',
      'Markdown fence check',
    );
  }

  if (!text.includes('Published researcher advisories:')) {
    text = replaceOnce(
      text,
      "notes.push(`Articles: ${articleFiles.length}`);\n",
      "notes.push(`Articles: ${articleFiles.length}`);\nnotes.push(`Published researcher advisories: ${researcherAdvisoryCount}`);\n",
      'scripts/qa-site.mjs',
      'article count note',
    );
  }

  return text;
});

console.log('h00die-gr3y v3.1 advisory integration');
console.log('-------------------------------------');
if (changed.length === 0) {
  console.log('No changes needed; v3.1 appears to be applied already.');
} else {
  for (const rel of changed) console.log(`UPDATED ${rel}`);
  console.log(`\nApplied ${changed.length} source updates.`);
}
