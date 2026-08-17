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

const astroFiles = walk(src).filter((file) => file.endsWith('.astro'));
const markdownFiles = walk(path.join(src, 'content')).filter((file) => file.endsWith('.md'));
const researchFiles = walk(path.join(src, 'content', 'research')).filter((file) => file.endsWith('.md'));
const kbFiles = walk(path.join(src, 'content', 'knowledge-base')).filter((file) => file.endsWith('.md'));
const articleFiles = walk(path.join(src, 'content', 'articles')).filter((file) => file.endsWith('.md'));

// Release counts: these catch accidental content loss before deployment.
if (researchFiles.length !== 63) failures.push(`Expected 63 research entries, found ${researchFiles.length}.`);
if (kbFiles.length !== 7) failures.push(`Expected 7 Knowledge Base entries, found ${kbFiles.length}.`);
if (articleFiles.length !== 1) failures.push(`Expected 1 article, found ${articleFiles.length}.`);

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

// Check Markdown code fences are balanced.
for (const file of markdownFiles) {
  const text = read(file);
  const fences = (text.match(/^```/gm) || []).length;
  if (fences % 2 !== 0) failures.push(`${rel(file)} has an unbalanced triple-backtick code fence.`);
}

notes.push(`Research entries: ${researchFiles.length}`);
notes.push(`Knowledge Base entries: ${kbFiles.length}`);
notes.push(`Articles: ${articleFiles.length}`);
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
