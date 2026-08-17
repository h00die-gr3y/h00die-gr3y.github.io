# Apply h00die-gr3y Astro v2.16

Apply this overlay after v2.15:

```bash
cd /Users/hgiessen/h00die-gr3y-astro
unzip -o ~/Downloads/h00die-gr3y-astro-source-v2.16.zip -d .
rm -rf .astro
node scripts/qa-site.mjs
npm run build
npm run dev
```

Recommended manual checks:

- Tab from the top of the page and confirm `Skip to content` appears.
- Confirm the current navigation section is highlighted.
- Test the Research/CVE filters with keyboard only.
- Check a long Research or Knowledge Base page at desktop, tablet and phone widths.
- Check a page containing a wide command/code block.
- Check the mobile menu around 600px and below.

Before committing:

```bash
node scripts/qa-site.mjs
npm run build
git diff
git status
```

See `RELEASE-QA.md` for the v2.16 changes.
