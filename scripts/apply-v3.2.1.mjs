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

const falsePositiveEntries = [
  'cve-2019-7252.md',
  'cve-2022-31706.md',
  'cve-2022-31791.md',
  'cve-2022-31814.md',
  'cve-2024-12992.md',
  'cve-2025-32433.md',
  'cve-2025-5965.md',
  'cve-2026-53804.md',
];

// 1. Correct the Exploit Development taxonomy. Payloads, manual reproduction
//    steps, third-party implementations and source stubs do not qualify.
for (const name of falsePositiveEntries) {
  const rel = `src/content/research/${name}`;
  update(rel, (text) => {
    if (/^exploitDevelopment:\s*false\s*$/m.test(text)) return text;
    if (!/^exploitDevelopment:\s*true\s*$/m.test(text)) {
      throw new Error(`${rel}: missing exploitDevelopment classification.`);
    }
    return text.replace(/^exploitDevelopment:\s*true\s*$/m, 'exploitDevelopment: false');
  });
}

// 2. Remove headings that previously called payload validation itself
//    "Exploit development". The underlying PoC/reproduction material remains.
for (const name of ['cve-2024-12992.md', 'cve-2025-5965.md']) {
  const rel = `src/content/research/${name}`;
  update(rel, (text) => text.replace(/\n## Exploit development\n\n[\s\S]*?(?=\n## )/, '\n'));
}

// 3. Make the public Exploits index describe the strict category boundary.
update('src/pages/exploits/index.astro', (text) => {
  const before = '<section class="page-hero"><div class="container"><span class="section-index">RESEARCH / EXPLOIT DEVELOPMENT</span><h1>Exploits</h1><p>{entries.length} research entries include practical exploit development. Public implementation links are shown when they are part of the research record; inline proof-of-concept work remains part of the research article itself.</p></div></section>';
  const after = '<section class="page-hero"><div class="container"><span class="section-index">RESEARCH / EXPLOIT DEVELOPMENT</span><h1>Exploits</h1><p>{entries.length} research entries include a concrete exploit implementation developed as part of the research work. Payloads, manual reproduction steps, inline validation commands and third-party exploit references alone do not qualify for this category.</p></div></section>';
  return replaceOnce(text, before, after, 'src/pages/exploits/index.astro', 'Exploit Development definition');
});

// 4. Encode the revised taxonomy in the maintained documentation.
const taxonomy = `# Research taxonomy — v3.2.1\n\n## Research origin\n\nEach entry has one primary origin:\n\n- \`original-research\`\n- \`technical-analysis\`\n\n## Research activity\n\n\`exploitDevelopment: true\` is reserved for research where a **concrete, reusable exploit implementation is part of the h00die-gr3y work submission**.\n\nQualifying examples include a Metasploit module, standalone exploit script, PoC tool or another separately identifiable implementation produced as part of the research.\n\nThe following do **not** qualify by themselves:\n\n- command-injection payloads or reverse-shell strings;\n- manual reproduction steps;\n- successful exploitation in a lab;\n- an inline marker command or callback;\n- a third-party exploit or module referenced for context;\n- a source stub that merely points to an available public module.\n\nA research article can therefore discuss exploitation in depth without being classified as **Exploit Development**.\n\n## Editorial status\n\n- \`polished\` — publication-quality website edit completed\n- \`normalized\` — structurally normalized but intentionally not promoted to polished when the source itself is only a stub\n- \`archived\` — reserved for untouched archive material\n\n## Exploit artifacts\n\nImplementation metadata and the Exploit Development category are related but not identical. \`exploitArtifacts\` may retain a relevant third-party implementation for context even when \`exploitDevelopment\` is \`false\`.\n\nFor entries classified as Exploit Development, at least one implementation must be attributable to the research work. Metasploit contribution pull requests and local h00die-gr3y research implementations provide direct provenance. A small audited set of older official modules is retained where the archived assessment explicitly states that h00die-gr3y created the implementation even though a contribution PR was not preserved in the metadata. CVE-2024-11320 is additionally retained as Exploit Development by explicit editorial decision because its research metadata contains the official Metasploit module artifact.\n`;
update('TAXONOMY.md', () => taxonomy);

const exploitDevelopmentDoc = `# Exploit development provenance — v3.2.1\n\nThis release tightens the **Exploit Development** category so it identifies implementation work rather than general exploitability or proof-of-concept validation.\n\n## Classification rule\n\nAn article is classified as \`exploitDevelopment: true\` only when a concrete, reusable exploit implementation is part of the h00die-gr3y work submission. Examples include a Metasploit module, standalone exploit script, PoC tool or equivalent implementation.\n\nPayload strings, reverse shells, manual reproduction steps, marker commands and successful exploitation alone are not sufficient. A third-party exploit reference also does not make the article h00die-gr3y Exploit Development work.\n\n## Implementation provenance\n\nFor Metasploit work, the website continues to use this precedence:\n\n1. If the research implementation exists in the official \`rapid7/metasploit-framework\` repository, publish the **Official module** link.\n2. If the contribution pull request is known, publish the **Contribution PR** alongside the official module.\n3. Do not publish a local development copy when an official module exists.\n4. If no official equivalent exists, a local h00die-gr3y research implementation may be used as the fallback.\n5. A PR or implementation belonging only to a related or chained vulnerability is not enough to classify the current article as Exploit Development.\n\n## v3.2.1 audit result\n\nThe complete 64-entry Research collection was reviewed against the stricter rule. Eight false positives were removed from the Exploit Development category; CVE-2024-11320 is explicitly retained by editorial decision.\n\n- **51** entries remain classified as Exploit Development.\n- **0** Exploit Development entries have an empty \`exploitArtifacts\` list.\n- Relevant third-party implementation links can remain attached to non-Exploit-Development research for context.\n- The 63-entry historical AttackerKB corpus and the site-native CVE-2026-53804 publication remain intact.\n\nThe detailed decisions are recorded in \`EXPLOIT-DEVELOPMENT-AUDIT-v3.2.1.md\`.\n`;
update('EXPLOIT-DEVELOPMENT.md', () => exploitDevelopmentDoc);

// 5. Historical migration summary: keep artifact inventory counts, but correct
//    the activity classification count and remove the old inline-only bucket.
update('CONTENT-SUMMARY.json', (text) => {
  const data = JSON.parse(text);
  data.exploit_development = 51;
  data.exploit_development_without_linked_artifact = 0;
  return `${JSON.stringify(data, null, 2)}\n`;
});

// 6. QA: enforce the revised boundary on every current and future Research entry.
update('scripts/qa-site.mjs', (text) => {
  if (!text.includes('const verifiedNoPrExploitDevelopment = new Set([')) {
    const block = `// v3.2.1 Exploit Development taxonomy.\n// A qualifying entry must expose an implementation that belongs to the research\n// contribution. PR/local implementation metadata is direct evidence; the small\n// allowlist below covers older archived work whose assessment explicitly records\n// researcher-created exploit code but whose PR was not preserved, plus the\n// explicit editorial retention of CVE-2024-11320.\nconst verifiedNoPrExploitDevelopment = new Set([\n  'cve-2021-39144.md',\n  'cve-2021-44529.md',\n  'cve-2022-33891.md',\n  'cve-2022-37061.md',\n  'cve-2022-44877.md',\n  'cve-2023-50919.md',\n  'cve-2024-11320.md',\n]);\n\nlet exploitDevelopmentCount = 0;\nfor (const file of researchFiles) {\n  const text = read(file);\n  const fm = frontmatter(text);\n  const name = path.basename(file);\n  const exploitDevelopment = /^exploitDevelopment:\\s*true\\s*$/m.test(fm);\n  const emptyArtifacts = /^exploitArtifacts:\\s*\\[\\]\\s*$/m.test(fm);\n  const contributionPr = /^\\s+pullRequestUrl:\\s*https:\\/\\/github\\.com\\/rapid7\\/metasploit-framework\\/pull\\/\\d+\\s*$/m.test(fm);\n  const localResearchImplementation = /^\\s+localUrl:\\s*https:\\/\\/github\\.com\\/h00die-gr3y\\//m.test(fm);\n  const verifiedHistoricalImplementation = verifiedNoPrExploitDevelopment.has(name);\n\n  if (exploitDevelopment) {\n    exploitDevelopmentCount += 1;\n    if (emptyArtifacts) {\n      failures.push(\`${'${rel(file)}'} is classified as Exploit Development but has no exploit artifact. Payloads/manual PoCs alone do not qualify.\`);\n    }\n    if (!contributionPr && !localResearchImplementation && !verifiedHistoricalImplementation) {\n      failures.push(\`${'${rel(file)}'} is classified as Exploit Development without researcher-contribution provenance.\`);\n    }\n  } else if (/^## Exploit development\\s*$/mi.test(text)) {\n    failures.push(\`${'${rel(file)}'} has an Exploit development heading while exploitDevelopment is false.\`);\n  }\n}\n\nif (exploitDevelopmentCount < 51) {\n  failures.push(\`Expected the audited Exploit Development baseline to remain at least 51 entries, found ${'${exploitDevelopmentCount}'}.\`);\n}\n\n`;
    text = replaceOnce(
      text,
      '// Every rendered main region must expose the skip-link target.\n',
      `${block}// Every rendered main region must expose the skip-link target.\n`,
      'scripts/qa-site.mjs',
      'v3.2.1 exploit taxonomy QA block',
    );
  }

  if (!text.includes('notes.push(`Exploit Development entries: ${exploitDevelopmentCount}`);')) {
    text = replaceOnce(
      text,
      'notes.push(`Canonical native CVE publication: CVE-2026-53804`);\n',
      'notes.push(`Canonical native CVE publication: CVE-2026-53804`);\nnotes.push(`Exploit Development entries: ${exploitDevelopmentCount}`);\n',
      'scripts/qa-site.mjs',
      'v3.2.1 QA count note',
    );
  }

  return text;
});

console.log('h00die-gr3y v3.2.1 Exploit Development taxonomy audit');
console.log('------------------------------------------------------');
if (changed.length === 0) {
  console.log('No changes needed; v3.2.1 appears to be applied already.');
} else {
  for (const rel of changed) console.log(`UPDATED ${rel}`);
  console.log(`\nApplied ${changed.length} source updates.`);
}
