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

// 1. Research schema: distinguish preserved AttackerKB material from research
//    first published directly on h00die-gr3y.
update('src/content.config.ts', (text) => {
  if (text.includes("provenance: z.enum(['attacker-kb-archive', 'site-native']).default('attacker-kb-archive')")) {
    return text;
  }

  return replaceOnce(
    text,
    "    source: z.object({\n      platform: z.string(),\n      url: z.string(),\n    }),\n",
    "    source: z.object({\n      provenance: z.enum(['attacker-kb-archive', 'site-native']).default('attacker-kb-archive'),\n      platform: z.string(),\n      url: z.string(),\n    }),\n",
    'src/content.config.ts',
    'research source schema',
  );
});

// 2. Research detail: render provenance correctly for archive and site-native work.
update('src/layouts/ResearchLayout.astro', (text) => {
  if (!text.includes("const sourceProvenance = data.source.provenance ?? 'attacker-kb-archive';")) {
    text = replaceOnce(
      text,
      "const typeLabel = data.researchType === 'original-research' ? 'ORIGINAL RESEARCH' : 'TECHNICAL ANALYSIS';\n",
      "const typeLabel = data.researchType === 'original-research' ? 'ORIGINAL RESEARCH' : 'TECHNICAL ANALYSIS';\nconst sourceProvenance = data.source.provenance ?? 'attacker-kb-archive';\nconst siteNativeResearch = sourceProvenance === 'site-native';\n",
      'src/layouts/ResearchLayout.astro',
      'research type label',
    );
  }

  text = replaceOnce(
    text,
    "        <div class=\"research-provenance\">\n          Originally published on {data.source.platform} · {data.published}\n          {data.revised !== data.published && <> · revised {data.revised}</>}\n        </div>\n",
    "        <div class=\"research-provenance\">\n          {siteNativeResearch ? <>Published by {data.source.platform}</> : <>Originally published on {data.source.platform}</>} · {data.published}\n          {data.revised !== data.published && <> · revised {data.revised}</>}\n        </div>\n",
    'src/layouts/ResearchLayout.astro',
    'research hero provenance',
  );

  text = replaceOnce(
    text,
    "              <div><dt>Source</dt><dd>{data.source.platform}</dd></div>\n",
    "              <div><dt>{siteNativeResearch ? 'Publication' : 'Source'}</dt><dd>{data.source.platform}</dd></div>\n",
    'src/layouts/ResearchLayout.astro',
    'research source metadata',
  );

  text = replaceOnce(
    text,
    "          <div class=\"meta-panel archive-note\">\n            <h2>Archive provenance</h2>\n            <p>This research was preserved from the h00die-gr3y AttackerKB archive before the platform's retirement.</p>\n          </div>\n",
    "          {siteNativeResearch ? (\n            <div class=\"meta-panel archive-note\">\n              <h2>Publication provenance</h2>\n              <p>First published by h00die-gr3y as part of this research site.</p>\n            </div>\n          ) : (\n            <div class=\"meta-panel archive-note\">\n              <h2>Archive provenance</h2>\n              <p>This research was preserved from the h00die-gr3y AttackerKB archive before the platform's retirement.</p>\n            </div>\n          )}\n",
    'src/layouts/ResearchLayout.astro',
    'archive provenance panel',
  );

  return text;
});

// 3. Archive cards: never label site-native research as an edited archive item.
update('src/components/ResearchArchive.astro', (text) => {
  if (!text.includes("const siteNativeResearch = (d.source.provenance ?? 'attacker-kb-archive') === 'site-native';")) {
    text = replaceOnce(
      text,
      "      const d = entry.data;\n      const originLabel = d.researchType === 'original-research' ? 'ORIGINAL RESEARCH' : 'TECHNICAL ANALYSIS';\n",
      "      const d = entry.data;\n      const siteNativeResearch = (d.source.provenance ?? 'attacker-kb-archive') === 'site-native';\n      const originLabel = d.researchType === 'original-research' ? 'ORIGINAL RESEARCH' : 'TECHNICAL ANALYSIS';\n",
      'src/components/ResearchArchive.astro',
      'archive entry data block',
    );
  }

  return replaceOnce(
    text,
    "            {d.editorialStatus !== 'archived' && <span>Edited archive</span>}\n",
    "            {!siteNativeResearch && d.editorialStatus !== 'archived' && <span>Edited archive</span>}\n",
    'src/components/ResearchArchive.astro',
    'edited archive label',
  );
});

// 4. Research index: describe the mixed historical + site-native collection.
update('src/pages/research/index.astro', (text) => {
  return replaceOnce(
    text,
    "        <p>Original discoveries, independent technical analysis and practical exploit development preserved from the h00die-gr3y research archive.</p>\n",
    "        <p>Original discoveries, independent technical analysis and practical exploit development — combining the preserved AttackerKB archive with research published directly by h00die-gr3y.</p>\n",
    'src/pages/research/index.astro',
    'research archive description',
  );
});

// 5. Exploits index: remove archive-only wording now that new research can be native.
update('src/pages/exploits/index.astro', (text) => {
  return replaceOnce(
    text,
    "    <section class=\"page-hero\"><div class=\"container\"><span class=\"section-index\">RESEARCH / EXPLOIT DEVELOPMENT</span><h1>Exploits</h1><p>{entries.length} research entries include practical exploit development. Public implementation links are shown when they are part of the archived research record; inline proof-of-concept work remains part of the research article itself.</p></div></section>\n",
    "    <section class=\"page-hero\"><div class=\"container\"><span class=\"section-index\">RESEARCH / EXPLOIT DEVELOPMENT</span><h1>Exploits</h1><p>{entries.length} research entries include practical exploit development. Public implementation links are shown when they are part of the research record; inline proof-of-concept work remains part of the research article itself.</p></div></section>\n",
    'src/pages/exploits/index.astro',
    'exploit archive description',
  );
});

// 6. Homepage: keep the fixed 63 count explicitly tied to the historical import.
update('src/pages/index.astro', (text) => {
  return replaceOnce(
    text,
    "        <div class=\"stat\"><strong>63</strong><span>Research assessments</span></div>\n",
    "        <div class=\"stat\"><strong>63</strong><span>AttackerKB entries</span></div>\n",
    'src/pages/index.astro',
    'historical archive count label',
  );
});

// 7. Release QA:
//    - allow the Research collection to grow beyond the 63-entry import;
//    - preserve the 63-entry AttackerKB baseline;
//    - reject embargoed .md content in the public repository;
//    - validate site-native publication provenance;
//    - count researcher advisories dynamically while still locking the three
//      historical researcher GHSAs to their original Research records.
update('scripts/qa-site.mjs', (text) => {
  text = replaceOnce(
    text,
    "if (researchFiles.length !== 63) failures.push(`Expected 63 research entries, found ${researchFiles.length}.`);\n",
    "if (researchFiles.length < 63) failures.push(`Expected at least 63 research entries, found ${researchFiles.length}.`);\n",
    'scripts/qa-site.mjs',
    'research release count',
  );

  if (!text.includes('function frontmatter(text)')) {
    text = replaceOnce(
      text,
      "function rel(file) {\n  return path.relative(root, file).replaceAll(path.sep, '/');\n}\n",
      "function rel(file) {\n  return path.relative(root, file).replaceAll(path.sep, '/');\n}\n\nfunction frontmatter(text) {\n  const match = text.match(/^---\\n([\\s\\S]*?)\\n---(?:\\n|$)/);\n  return match?.[1] ?? '';\n}\n",
      'scripts/qa-site.mjs',
      'relative path helper',
    );
  }

  // Rename the v3.1 historical counter before adding the dynamic all-advisory counter.
  text = text.replace(
    "]);\nlet researcherAdvisoryCount = 0;\nfor (const [name, ghsa] of expectedResearcherAdvisories) {",
    "]);\nlet historicalResearcherAdvisoryCount = 0;\nfor (const [name, ghsa] of expectedResearcherAdvisories) {",
  );
  text = text.replace(
    "  researcherAdvisoryCount += 1;\n}\n\nconst advisoriesPage",
    "  historicalResearcherAdvisoryCount += 1;\n}\n\nconst advisoriesPage",
  );

  if (!text.includes('let siteNativeResearchCount = 0;')) {
    const provenanceChecks = `// Research publication provenance and public-repository embargo guard.\nlet siteNativeResearchCount = 0;\nlet attackerKbArchiveCount = 0;\nlet researcherAdvisoryCount = 0;\n\nfor (const file of researchFiles) {\n  const fm = frontmatter(read(file));\n  const sourceBlock = fm.match(/^source:\\n((?: {2}[^\\n]*\\n?)*)/m)?.[1] ?? '';\n  const siteNativeResearch = /^ {2}provenance:\\s*site-native\\s*$/m.test(sourceBlock);\n  const sitePlatform = /^ {2}platform:\\s*['\\\"]?h00die-gr3y['\\\"]?\\s*$/m.test(sourceBlock);\n  const canonicalNativeUrl = /^ {2}url:\\s*['\\\"]?https:\\/\\/h00die-gr3y\\.github\\.io\\/research\\/[^'\\\"\\s]+\\/?['\\\"]?\\s*$/m.test(sourceBlock);\n  const embargoed = /^\\s+status:\\s*embargoed\\s*$/m.test(fm);\n\n  researcherAdvisoryCount += (fm.match(/^\\s*-\\s+type:\\s+researcher\\s*$/gm) || []).length;\n\n  if (embargoed) {\n    failures.push(\`\${rel(file)} is marked embargoed but is stored in the public Research collection. Keep embargoed research outside this repository.\`);\n  }\n\n  if (siteNativeResearch) {\n    siteNativeResearchCount += 1;\n    if (!sitePlatform) failures.push(\`\${rel(file)} uses site-native provenance but source.platform is not h00die-gr3y.\`);\n    if (!canonicalNativeUrl) failures.push(\`\${rel(file)} uses site-native provenance but source.url is not its canonical /research/ URL.\`);\n    if (/Rapid7 AttackerKB/i.test(sourceBlock)) failures.push(\`\${rel(file)} mixes site-native provenance with an AttackerKB source.\`);\n  } else {\n    attackerKbArchiveCount += 1;\n    if (sitePlatform) failures.push(\`\${rel(file)} uses source.platform h00die-gr3y without source.provenance: site-native.\`);\n  }\n}\n\nif (attackerKbArchiveCount !== 63) {\n  failures.push(\`Expected the preserved AttackerKB baseline to remain 63 entries, found \${attackerKbArchiveCount}.\`);\n}\n\nconst contentConfig = read(path.join(src, 'content.config.ts'));\nif (!contentConfig.includes(\"provenance: z.enum(['attacker-kb-archive', 'site-native']).default('attacker-kb-archive')\")) {\n  failures.push('Research schema is missing source provenance support.');\n}\nconst researchLayout = read(path.join(src, 'layouts', 'ResearchLayout.astro'));\nif (!researchLayout.includes(\"sourceProvenance = data.source.provenance ?? 'attacker-kb-archive'\")) {\n  failures.push('Research layout is missing site-native provenance handling.');\n}\nconst researchArchive = read(path.join(src, 'components', 'ResearchArchive.astro'));\nif (!researchArchive.includes(\"!siteNativeResearch && d.editorialStatus !== 'archived'\")) {\n  failures.push('Research archive can incorrectly label site-native research as an edited archive item.');\n}\n\n`;

    text = replaceOnce(
      text,
      "// Every rendered main region must expose the skip-link target.\n",
      `${provenanceChecks}// Every rendered main region must expose the skip-link target.\n`,
      'scripts/qa-site.mjs',
      'main-region accessibility check',
    );
  }

  text = text.replace(
    "notes.push(`Published researcher advisories: ${researcherAdvisoryCount}`);\n",
    "notes.push(`AttackerKB archive entries: ${attackerKbArchiveCount}`);\nnotes.push(`Site-native research entries: ${siteNativeResearchCount}`);\nnotes.push(`Structured researcher advisories: ${researcherAdvisoryCount}`);\nnotes.push(`Protected historical researcher advisories: ${historicalResearcherAdvisoryCount}`);\n",
  );

  return text;
});

// 8. Documentation: make provenance and embargo handling part of the disclosure model.
update('DISCLOSURE-ADVISORIES.md', (text) => {
  text = text.replace(
    '# Disclosure and advisory model — v3.1\n',
    '# Disclosure and advisory model — v3.1.1\n',
  );
  text = text.replace(
    'Historical entries are not retroactively assigned HGR numbers in v3.1.\n',
    'Historical entries are not retroactively assigned HGR numbers in v3.1.1.\n',
  );

  if (!text.includes('## Research publication provenance')) {
    text += `\n## Research publication provenance\n\nResearch content now has an explicit source provenance model:\n\n- \`attacker-kb-archive\` — preserved research imported from the historical AttackerKB archive. This is the schema default so the existing 63 entries require no frontmatter rewrite.\n- \`site-native\` — research first published directly by h00die-gr3y on this site.\n\nA future site-native Research entry should use:\n\n\`\`\`yaml\nsource:\n  provenance: site-native\n  platform: h00die-gr3y\n  url: https://h00die-gr3y.github.io/research/<slug>/\n\`\`\`\n\nThe Research layout uses that field to distinguish **Originally published on ...** archive provenance from **Published by h00die-gr3y** site-native provenance. Site-native entries are also excluded from the **Edited archive** label.\n\n## Embargo boundary\n\nAn \`embargoed\` status is schema-valid because private drafts use the same content model, but embargoed Markdown must never be committed to this public repository. Release QA now fails if a public \`src/content/research/*.md\` file contains \`disclosure.status: embargoed\`.\n\nKeep private drafts outside the repository (or with a non-\`.md\` extension in a private workspace) until coordinated public disclosure. At publication, change the source provenance to \`site-native\`, set the canonical site URL and resolve the final disclosure metadata before moving the article into \`src/content/research/\`.\n`;
  }

  return text;
});

console.log('h00die-gr3y v3.1.1 native-research provenance patch');
console.log('----------------------------------------------------');
if (changed.length === 0) {
  console.log('No changes needed; v3.1.1 appears to be applied already.');
} else {
  for (const rel of changed) console.log(`UPDATED ${rel}`);
  console.log(`\nApplied ${changed.length} source updates.`);
}
