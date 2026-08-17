#!/usr/bin/env node
import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = process.cwd();
const CONTENT_DIR = path.join(ROOT, 'src', 'content', 'research');
const PUBLIC_DIR = path.join(ROOT, 'public');
const mappings = [
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2020-35665/Screenshot_DEADBOLT.png",
    "slug": "cve-2020-35665",
    "filename": "Screenshot_DEADBOLT.png",
    "localUrl": "/images/research/cve-2020-35665/Screenshot_DEADBOLT.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2023-2068/FMA_shortcode_plugin_linux_auth_rce.png",
    "slug": "cve-2023-2068",
    "filename": "FMA_shortcode_plugin_linux_auth_rce.png",
    "localUrl": "/images/research/cve-2023-2068/FMA_shortcode_plugin_linux_auth_rce.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2024-12971/cve-2024-12971-chromium-path-rce.png",
    "slug": "cve-2024-12971",
    "filename": "cve-2024-12971-chromium-path-rce.png",
    "localUrl": "/images/research/cve-2024-12971/cve-2024-12971-chromium-path-rce.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2024-12992/cve-2024-12992-quickshell.png",
    "slug": "cve-2024-12992",
    "filename": "cve-2024-12992-quickshell.png",
    "localUrl": "/images/research/cve-2024-12992/cve-2024-12992-quickshell.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-30406/burpsuite__viewstate_deserialization.png",
    "slug": "cve-2025-30406",
    "filename": "burpsuite__viewstate_deserialization.png",
    "localUrl": "/images/research/cve-2025-30406/burpsuite__viewstate_deserialization.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-30406/burpsuite__viewstategenerator.png",
    "slug": "cve-2025-30406",
    "filename": "burpsuite__viewstategenerator.png",
    "localUrl": "/images/research/cve-2025-30406/burpsuite__viewstategenerator.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-4653/backup_name_RCE.png",
    "slug": "cve-2025-4653",
    "filename": "backup_name_RCE.png",
    "localUrl": "/images/research/cve-2025-4653/backup_name_RCE.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-4653/http_listener.png",
    "slug": "cve-2025-4653",
    "filename": "http_listener.png",
    "localUrl": "/images/research/cve-2025-4653/http_listener.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_data_trigger.png",
    "slug": "cve-2025-5946",
    "filename": "centreon_data_trigger.png",
    "localUrl": "/images/research/cve-2025-5946/centreon_data_trigger.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_metric_trigger.png",
    "slug": "cve-2025-5946",
    "filename": "centreon_metric_trigger.png",
    "localUrl": "/images/research/cve-2025-5946/centreon_metric_trigger.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_poller_configuration.png",
    "slug": "cve-2025-5946",
    "filename": "centreon_poller_configuration.png",
    "localUrl": "/images/research/cve-2025-5946/centreon_poller_configuration.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_poller_export.png",
    "slug": "cve-2025-5946",
    "filename": "centreon_poller_export.png",
    "localUrl": "/images/research/cve-2025-5946/centreon_poller_export.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5946/centreon_poller_list.png",
    "slug": "cve-2025-5946",
    "filename": "centreon_poller_list.png",
    "localUrl": "/images/research/cve-2025-5946/centreon_poller_list.png"
  },
  {
    "url": "https://raw.githubusercontent.com/h00die-gr3y/Metasploit/main/attackerkb/cve-2025-5965/centreon_backup_configuration.png",
    "slug": "cve-2025-5965",
    "filename": "centreon_backup_configuration.png",
    "localUrl": "/images/research/cve-2025-5965/centreon_backup_configuration.png"
  }
];

async function exists(file) {
  try { await access(file, fsConstants.F_OK); return true; } catch { return false; }
}

async function download(url, destination) {
  const response = await fetch(url, {
    redirect: 'follow',
    headers: { 'User-Agent': 'h00die-gr3y-astro-image-migration/1.0' }
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText} for ${url}`);
  const type = response.headers.get('content-type') || '';
  if (!type.startsWith('image/')) throw new Error(`Expected image content for ${url}, got ${type || 'unknown content type'}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length < 8) throw new Error(`Downloaded image is unexpectedly small: ${url}`);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, bytes);
  return bytes.length;
}

let downloaded = 0;
let reused = 0;
let replacements = 0;

console.log(`Migrating ${mappings.length} research images to public/images/research/...`);

for (const item of mappings) {
  const destination = path.join(PUBLIC_DIR, item.localUrl.replace(/^\//, ''));
  if (await exists(destination)) {
    reused++;
    console.log(`  = ${item.localUrl}`);
  } else {
    const size = await download(item.url, destination);
    downloaded++;
    console.log(`  + ${item.localUrl} (${Math.round(size / 1024)} KiB)`);
  }
}

const contentFiles = new Set();
for (const item of mappings) {
  // Determine the article from the CVE/research slug used in the source URL.
  const expected = path.join(CONTENT_DIR, `${item.slug}.md`);
  if (await exists(expected)) contentFiles.add(expected);
}

// A few future assets may use a source-directory slug that differs from the article filename,
// so scan all Markdown files referenced by the current mapping as a fallback.
const { readdir } = await import('node:fs/promises');
for (const name of await readdir(CONTENT_DIR)) {
  if (name.endsWith('.md')) contentFiles.add(path.join(CONTENT_DIR, name));
}

for (const file of [...contentFiles].sort()) {
  let text = await readFile(file, 'utf8');
  const before = text;
  for (const item of mappings) {
    if (text.includes(item.url)) {
      text = text.split(item.url).join(item.localUrl);
      replacements++;
    }
  }
  if (text !== before) await writeFile(file, text, 'utf8');
}

// Validate migration: no mapped remote image URL may remain and each local file must exist.
let failures = [];
for (const name of await readdir(CONTENT_DIR)) {
  if (!name.endsWith('.md')) continue;
  const file = path.join(CONTENT_DIR, name);
  const text = await readFile(file, 'utf8');
  for (const item of mappings) {
    if (text.includes(item.url)) failures.push(`${name}: remote URL still present: ${item.url}`);
  }
}
for (const item of mappings) {
  const destination = path.join(PUBLIC_DIR, item.localUrl.replace(/^\//, ''));
  if (!(await exists(destination))) failures.push(`Missing local asset: ${item.localUrl}`);
}

if (failures.length) {
  console.error('\nMigration validation failed:');
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(`\nDone. Downloaded ${downloaded}, reused ${reused}, rewrote ${replacements} image references.`);
console.log('Original files under archive/attackerkb/ were not modified.');
console.log('Next: npm run build, then git add public/images/research src/content/research');
