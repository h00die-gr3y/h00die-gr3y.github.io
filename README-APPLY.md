# Apply h00die-gr3y v3.2.1

v3.2.1 audits and corrects the **Exploit Development** taxonomy. It is designed to apply over a worktree where **v3.2 is already applied**.

```bash
cd /Users/hgiessen/h00die-gr3y-astro

git pull
unzip -o ~/Downloads/h00die-gr3y-astro-source-v3.2.1.zip -d .
node scripts/apply-v3.2.1.mjs

rm -rf .astro
node scripts/qa-site.mjs
npm run build
npm run dev
```

Review these areas locally:

- `/exploits/` — expected **51** qualifying entries on the current 64-entry corpus
- `/research/` — Exploit Development count should be **51**
- `/research/cve-2024-12992/` — no Exploit Development label/heading
- `/research/cve-2025-5965/` — no Exploit Development label/heading
- `/research/cve-2026-53804/` — remains Original Research, but is not Exploit Development
- `/research/cve-2024-11320/` — remains categorized as **Exploit Development** by explicit editorial decision
- `/research/cve-2022-31706/`, `/research/cve-2022-31814/`, `/research/cve-2025-32433/` — implementation references may remain, but the research is not categorized as Exploit Development

Expected release-model state:

- Research entries: **64**
- AttackerKB archive entries: **63**
- Site-native Research entries: **1**
- Exploit Development entries: **51**
- Exploit Development entries with empty artifact lists: **0**
- Structured researcher advisories: **3**

Before publishing:

```bash
git status
git diff
```

When satisfied:

```bash
git add .
git commit -m "Audit Exploit Development taxonomy v3.2.1"
git push
```
