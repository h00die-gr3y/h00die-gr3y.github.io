#!/usr/bin/env node

import { access, copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const sourceRoot = path.resolve(process.argv[2] || '../h00die-gr3y.github.io');

const assets = [
  {
    source: 'assets/images/petitpotam.png',
    destination: 'public/images/knowledge-base/active-directory-attack-techniques/petitpotam.png',
  },
  {
    source: 'assets/images/transpeed-6k.png',
    destination: 'public/images/knowledge-base/uart-shell-access/transpeed-6k.png',
  },
  {
    source: 'assets/images/pcb-transpeed-6k.png',
    destination: 'public/images/knowledge-base/uart-shell-access/pcb-transpeed-6k.png',
  },
  {
    source: 'assets/images/uart-diagram.png',
    destination: 'public/images/knowledge-base/uart-shell-access/uart-diagram.png',
  },
  {
    source: 'assets/images/uart-test-bed.jpg',
    destination: 'public/images/knowledge-base/uart-shell-access/uart-test-bed.jpg',
  },
];

async function exists(file) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

let copied = 0;
const missing = [];

for (const asset of assets) {
  const source = path.join(sourceRoot, asset.source);
  const destination = path.resolve(asset.destination);

  if (!(await exists(source))) {
    missing.push(source);
    continue;
  }

  await mkdir(path.dirname(destination), { recursive: true });
  await copyFile(source, destination);
  console.log(`copied: ${source} -> ${destination}`);
  copied += 1;
}

console.log(`\nKnowledge Base assets: ${copied}/${assets.length} copied.`);

if (missing.length) {
  console.error('\nMissing source assets:');
  for (const file of missing) console.error(`- ${file}`);
  process.exitCode = 1;
}
