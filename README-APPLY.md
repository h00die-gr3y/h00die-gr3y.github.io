# Apply h00die-gr3y v3.1.1

This patch prepares the current v3.1 site for research that is first published directly on h00die-gr3y instead of being migrated from AttackerKB.

It does **not** publish CVE-2026-53804 or any other embargoed research.

Apply it over the current `redesign-astro` worktree:

```bash
cd /Users/hgiessen/h00die-gr3y-astro

git pull
unzip -o ~/Downloads/h00die-gr3y-astro-source-v3.1.1.zip -d .
node scripts/apply-v3.1.1.mjs

node scripts/qa-site.mjs
npm run build
npm run dev
```

Review these areas:

- `/research/`
- `/exploits/`
- several existing Research detail pages
- homepage archive statistics
- `DISCLOSURE-ADVISORIES.md`

The visible behavior of the existing 63 AttackerKB entries should remain the same except for wording that is now explicitly archive-specific.

Before publishing:

```bash
git status
git diff
```

When satisfied:

```bash
git add .
git commit -m "Add native research provenance v3.1.1"
git push
```

The existing GitHub Action will run release QA, build Astro and deploy `dist/` to production.

## Future site-native frontmatter

At coordinated public disclosure, a new native Research entry should include:

```yaml
source:
  provenance: site-native
  platform: h00die-gr3y
  url: https://h00die-gr3y.github.io/research/<slug>/
```

Existing migrated Research entries do not need changes: the schema defaults missing provenance to `attacker-kb-archive`.

Release QA now also rejects `disclosure.status: embargoed` inside public `src/content/research/*.md` files. Embargoed drafts must remain outside the public repository.
