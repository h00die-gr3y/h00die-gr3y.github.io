#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const root = process.cwd();
const src = path.join(root, 'src');
const failures = [];
const notes = [];

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

function read(file) {
  return fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
}

function rel(file) {
  return path.relative(root, file).replaceAll(path.sep, '/');
}

function frontmatter(text) {
  const match = text.match(/^---\n([\s\S]*?)\n---(?:\n|$)/);
  return match?.[1] ?? '';
}

const astroFiles = walk(src).filter((file) => file.endsWith('.astro'));
const markdownFiles = walk(path.join(src, 'content')).filter((file) => file.endsWith('.md'));
const researchFiles = walk(path.join(src, 'content', 'research')).filter((file) => file.endsWith('.md'));
const kbFiles = walk(path.join(src, 'content', 'knowledge-base')).filter((file) => file.endsWith('.md'));
const articleFiles = walk(path.join(src, 'content', 'articles')).filter((file) => file.endsWith('.md'));

// Release counts: these catch accidental content loss before deployment.
if (researchFiles.length < 64) failures.push(`Expected at least 64 research entries, found ${researchFiles.length}.`);
if (kbFiles.length !== 7) failures.push(`Expected 7 Knowledge Base entries, found ${kbFiles.length}.`);
if (articleFiles.length !== 1) failures.push(`Expected 1 article, found ${articleFiles.length}.`);

// Research publication provenance and public-repository embargo guard.
let siteNativeResearchCount = 0;
let attackerKbArchiveCount = 0;
let researcherAdvisoryCount = 0;

for (const file of researchFiles) {
  const fm = frontmatter(read(file));
  const sourceBlock = fm.match(/^source:\n((?: {2}[^\n]*\n?)*)/m)?.[1] ?? '';
  const siteNativeResearch = /^ {2}provenance:\s*site-native\s*$/m.test(sourceBlock);
  const sitePlatform = /^ {2}platform:\s*['\"]?h00die-gr3y['\"]?\s*$/m.test(sourceBlock);
  const canonicalNativeUrl = /^ {2}url:\s*['\"]?https:\/\/h00die-gr3y\.github\.io\/research\/[^'\"\s]+\/?['\"]?\s*$/m.test(sourceBlock);
  const embargoed = /^\s+status:\s*embargoed\s*$/m.test(fm);

  researcherAdvisoryCount += (fm.match(/^\s*-\s+type:\s+researcher\s*$/gm) || []).length;

  if (embargoed) {
    failures.push(`${rel(file)} is marked embargoed but is stored in the public Research collection. Keep embargoed research outside this repository.`);
  }

  if (siteNativeResearch) {
    siteNativeResearchCount += 1;
    if (!sitePlatform) failures.push(`${rel(file)} uses site-native provenance but source.platform is not h00die-gr3y.`);
    if (!canonicalNativeUrl) failures.push(`${rel(file)} uses site-native provenance but source.url is not its canonical /research/ URL.`);
    if (/Rapid7 AttackerKB/i.test(sourceBlock)) failures.push(`${rel(file)} mixes site-native provenance with an AttackerKB source.`);
  } else {
    attackerKbArchiveCount += 1;
    if (sitePlatform) failures.push(`${rel(file)} uses source.platform h00die-gr3y without source.provenance: site-native.`);
  }
}

if (attackerKbArchiveCount !== 63) {
  failures.push(`Expected the preserved AttackerKB baseline to remain 63 entries, found ${attackerKbArchiveCount}.`);
}

const contentConfig = read(path.join(src, 'content.config.ts'));
if (!contentConfig.includes("provenance: z.enum(['attacker-kb-archive', 'site-native']).default('attacker-kb-archive')")) {
  failures.push('Research schema is missing source provenance support.');
}
const researchLayout = read(path.join(src, 'layouts', 'ResearchLayout.astro'));
if (!researchLayout.includes("sourceProvenance = data.source.provenance ?? 'attacker-kb-archive'")) {
  failures.push('Research layout is missing site-native provenance handling.');
}
const researchArchive = read(path.join(src, 'components', 'ResearchArchive.astro'));
if (!researchArchive.includes("!siteNativeResearch && d.editorialStatus !== 'archived'")) {
  failures.push('Research archive can incorrectly label site-native research as an edited archive item.');
}

// v3.2 canonical site-native publication.
const canonicalNativeCve = 'cve-2026-53804.md';
const canonicalNativeCveFile = researchFiles.find((candidate) => path.basename(candidate) === canonicalNativeCve);
if (!canonicalNativeCveFile) {
  failures.push(`Missing canonical Research publication: ${canonicalNativeCve}.`);
} else {
  const canonicalText = read(canonicalNativeCveFile);
  const canonicalFm = frontmatter(canonicalText);
  if (!/^cve:\s*CVE-2026-53804\s*$/m.test(canonicalFm)) failures.push(`${rel(canonicalNativeCveFile)} is missing CVE-2026-53804 metadata.`);
  if (!/^researchType:\s*original-research\s*$/m.test(canonicalFm)) failures.push(`${rel(canonicalNativeCveFile)} must be Original Research.`);
  if (!/^ {2}provenance:\s*site-native\s*$/m.test(canonicalFm)) failures.push(`${rel(canonicalNativeCveFile)} must use site-native provenance.`);
  if (!/^ {2}url:\s*https:\/\/h00die-gr3y\.github\.io\/research\/cve-2026-53804\/\s*$/m.test(canonicalFm)) failures.push(`${rel(canonicalNativeCveFile)} has the wrong canonical source URL.`);
  if (!/^ {2}status:\s*published\s*$/m.test(canonicalFm)) failures.push(`${rel(canonicalNativeCveFile)} must be published.`);
  if (!/^ {2}credit:\s*h00die-gr3y — Finder\s*$/m.test(canonicalFm)) failures.push(`${rel(canonicalNativeCveFile)} is missing finder credit.`);
  if (!/^ {2}advisories:\s*\[\]\s*$/m.test(canonicalFm)) failures.push(`${rel(canonicalNativeCveFile)} must not create an advisory record.`);
  if (/security\/advisories/i.test(canonicalText)) failures.push(`${rel(canonicalNativeCveFile)} contains a researcher-advisory reference.`);
  if (!canonicalText.includes('Kernel/System/Crypt/PGP.pm')) failures.push(`${rel(canonicalNativeCveFile)} is missing the PGP.pm root-cause path.`);
  if (!canonicalText.includes('PGP::Bin') || !canonicalText.includes('PGP::Options')) failures.push(`${rel(canonicalNativeCveFile)} is missing the affected PGP settings.`);
}

const disclosurePanelV32 = read(path.join(src, 'components', 'DisclosurePanel.astro'));
if (disclosurePanelV32.includes('disclosure && disclosure.advisories?.length > 0')) {
  failures.push('DisclosurePanel still hides published disclosure metadata when there are no advisory records.');
}

// v3.2.1 Exploit Development taxonomy.
// A qualifying entry must expose an implementation that belongs to the research
// contribution. PR/local implementation metadata is direct evidence; the small
// allowlist below covers older archived work whose assessment explicitly records
// researcher-created exploit code but whose PR was not preserved, plus the
// explicit editorial retention of CVE-2024-11320.
const verifiedNoPrExploitDevelopment = new Set([
  'cve-2021-39144.md',
  'cve-2021-44529.md',
  'cve-2022-33891.md',
  'cve-2022-37061.md',
  'cve-2022-44877.md',
  'cve-2023-50919.md',
  'cve-2024-11320.md',
]);

let exploitDevelopmentCount = 0;
for (const file of researchFiles) {
  const text = read(file);
  const fm = frontmatter(text);
  const name = path.basename(file);
  const exploitDevelopment = /^exploitDevelopment:\s*true\s*$/m.test(fm);
  const emptyArtifacts = /^exploitArtifacts:\s*\[\]\s*$/m.test(fm);
  const contributionPr = /^\s+pullRequestUrl:\s*https:\/\/github\.com\/rapid7\/metasploit-framework\/pull\/\d+\s*$/m.test(fm);
  const localResearchImplementation = /^\s+localUrl:\s*https:\/\/github\.com\/h00die-gr3y\//m.test(fm);
  const verifiedHistoricalImplementation = verifiedNoPrExploitDevelopment.has(name);

  if (exploitDevelopment) {
    exploitDevelopmentCount += 1;
    if (emptyArtifacts) {
      failures.push(`${rel(file)} is classified as Exploit Development but has no exploit artifact. Payloads/manual PoCs alone do not qualify.`);
    }
    if (!contributionPr && !localResearchImplementation && !verifiedHistoricalImplementation) {
      failures.push(`${rel(file)} is classified as Exploit Development without researcher-contribution provenance.`);
    }
  } else if (/^## Exploit development\s*$/mi.test(text)) {
    failures.push(`${rel(file)} has an Exploit development heading while exploitDevelopment is false.`);
  }
}

if (exploitDevelopmentCount < 51) {
  failures.push(`Expected the audited Exploit Development baseline to remain at least 51 entries, found ${exploitDevelopmentCount}.`);
}

// Every rendered main region must expose the skip-link target.
for (const file of astroFiles) {
  const text = read(file);
  if (text.includes('<main') && !text.includes('id="main-content"')) {
    failures.push(`${rel(file)} contains <main> without id="main-content".`);
  }
}

const header = read(path.join(src, 'components', 'Header.astro'));
if (!header.includes('href="#main-content"')) failures.push('Header is missing the skip-to-content link.');
if (!header.includes('aria-current=')) failures.push('Header is missing aria-current navigation state.');

// External links opened in a new tab need the defensive rel attribute.
for (const file of astroFiles) {
  const text = read(file);
  for (const match of text.matchAll(/<a\b[^>]*target=["']_blank["'][^>]*>/gi)) {
    if (!/rel=["'][^"']*noopener[^"']*noreferrer[^"']*["']/i.test(match[0])) {
      failures.push(`${rel(file)} has target="_blank" without rel="noopener noreferrer".`);
    }
  }
}

// Keep the Knowledge Base voice standalone and practical.
const bannedKbPhrases = [
  /\boriginal article\b/i,
  /\boriginal lab\b/i,
  /\blegacy source\b/i,
  /\bpreviously published\b/i,
  /\bold page\b/i,
  /\boepsie\b/i,
  /\bbeen there\b/i,
  /\bcool proof(?: of concept)?\b/i,
  /\bnice example\b/i,
  /\bprimitives?\b/i,
];
for (const file of kbFiles) {
  const text = read(file);
  for (const pattern of bannedKbPhrases) {
    if (pattern.test(text)) failures.push(`${rel(file)} contains discouraged wording matching ${pattern}.`);
  }
}

const researchSlugs = new Set(researchFiles.map((file) => path.basename(file, '.md')));
const kbSlugs = new Set(kbFiles.map((file) => path.basename(file, '.md')));
const articleSlugs = new Set(articleFiles.map((file) => path.basename(file, '.md')));

// Validate literal cross-links inside Markdown. Dynamic Astro links are intentionally excluded.
for (const file of markdownFiles) {
  const text = read(file);
  for (const match of text.matchAll(/\]\((\/(?:research|knowledge-base|articles)\/([^/)#?]+)\/?(?:#[^)]*)?)\)/g)) {
    const url = match[1];
    const slug = match[2];
    if (url.startsWith('/research/') && !researchSlugs.has(slug)) failures.push(`${rel(file)} links to missing research entry: ${url}`);
    if (url.startsWith('/knowledge-base/') && !kbSlugs.has(slug)) failures.push(`${rel(file)} links to missing Knowledge Base entry: ${url}`);
    if (url.startsWith('/articles/') && !articleSlugs.has(slug)) failures.push(`${rel(file)} links to missing article: ${url}`);
  }
}


// Disclosure/advisory integration: the three historical researcher GHSAs must remain attached
// to their existing first-class Research entries, not duplicated as separate content.
const expectedResearcherAdvisories = new Map([
  ['cve-2025-4653.md', 'GHSA-m4f8-9c8x-8f3f'],
  ['cve-2025-4678.md', 'GHSA-wcqx-vw37-9pv8'],
  ['cve-2025-5946.md', 'GHSA-g6r8-jjf7-w7gh'],
]);
let historicalResearcherAdvisoryCount = 0;
for (const [name, ghsa] of expectedResearcherAdvisories) {
  const target = researchFiles.find((candidate) => path.basename(candidate) === name);
  if (!target) {
    failures.push(`Missing Research entry expected for ${ghsa}: ${name}.`);
    continue;
  }
  const text = read(target);
  if (!text.includes(`id: ${ghsa}`)) failures.push(`${rel(target)} is missing structured advisory ${ghsa}.`);
  if (!text.includes('type: researcher')) failures.push(`${rel(target)} is missing researcher advisory classification.`);
  const referencesBody = text.split('## References')[1]?.split('## ')[0] ?? '';
  if (referencesBody.includes(ghsa)) failures.push(`${rel(target)} duplicates ${ghsa} in the body References section.`);
  historicalResearcherAdvisoryCount += 1;
}

const advisoriesPage = path.join(src, 'pages', 'advisories', 'index.astro');
if (!fs.existsSync(advisoriesPage)) failures.push('Missing /advisories/ page.');
const sitemap = read(path.join(src, 'pages', 'sitemap.xml.ts'));
if (!sitemap.includes("{ path: '/advisories/'")) failures.push('Sitemap is missing /advisories/.');

// Check Markdown code fences are balanced.
for (const file of markdownFiles) {
  const text = read(file);
  const fences = (text.match(/^```/gm) || []).length;
  if (fences % 2 !== 0) failures.push(`${rel(file)} has an unbalanced triple-backtick code fence.`);
}

notes.push(`Research entries: ${researchFiles.length}`);
notes.push(`Knowledge Base entries: ${kbFiles.length}`);
notes.push(`Articles: ${articleFiles.length}`);
notes.push(`AttackerKB archive entries: ${attackerKbArchiveCount}`);
notes.push(`Site-native research entries: ${siteNativeResearchCount}`);
notes.push(`Structured researcher advisories: ${researcherAdvisoryCount}`);
notes.push(`Canonical native CVE publication: CVE-2026-53804`);
notes.push(`Exploit Development entries: ${exploitDevelopmentCount}`);
notes.push(`Protected historical researcher advisories: ${historicalResearcherAdvisoryCount}`);
notes.push(`Astro files checked: ${astroFiles.length}`);
notes.push(`Markdown files checked: ${markdownFiles.length}`);

console.log('h00die-gr3y release QA');
console.log('-----------------------');
for (const note of notes) console.log(`OK  ${note}`);

if (failures.length) {
  console.error(`\nFAILED: ${failures.length} issue${failures.length === 1 ? '' : 's'} found`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log('\nPASS: release QA checks completed without errors.');
