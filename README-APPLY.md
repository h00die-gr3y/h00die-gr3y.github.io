# Apply h00die-gr3y v3.1

Apply this package over the current `redesign-astro` worktree.

```bash
cd /Users/hgiessen/h00die-gr3y-astro

git pull
unzip -o ~/Downloads/h00die-gr3y-astro-source-v3.1.zip -d .
node scripts/apply-v3.1.mjs

node scripts/qa-site.mjs
npm run build
npm run dev
```

Review:

- `/advisories/`
- `/research/cve-2025-4653/`
- `/research/cve-2025-4678/`
- `/research/cve-2025-5946/`
- `/research/`
- `/about/`

Before publishing:

```bash
git status
git diff
```

When satisfied:

```bash
git add .
git commit -m "Add disclosure and advisory integration v3.1"
git push
```

The existing GitHub Action will then run QA, build Astro and deploy `dist/` to the production `master` branch.
