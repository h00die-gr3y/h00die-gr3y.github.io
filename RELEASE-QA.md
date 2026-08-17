# v2.16 — Final QA and release hardening

This is the final cleanup pass before the v3.0 production release.

## Accessibility

- Added a keyboard-visible `Skip to content` link.
- Added a stable `#main-content` target to every rendered main region.
- Added `aria-current="page"` to desktop and mobile navigation.
- Added visible keyboard focus states for links and form controls.
- External links that open a new tab now expose that behavior to screen readers.
- Research filters expose their result area and announce the visible result count.
- Increased the muted-text contrast used by small metadata labels.
- Added `prefers-reduced-motion` handling.

## Responsive hardening

- Improved mobile navigation target sizing.
- Long code blocks remain horizontally scrollable instead of forcing page overflow.
- Markdown tables now scroll within the content column on narrow screens.
- Long technical strings can wrap safely in cards and article bodies.
- Footer and feature metadata wrap cleanly on narrow screens.

## Release QA script

Run:

```bash
node scripts/qa-site.mjs
```

The dependency-free script checks the expected content counts, skip-link targets, external-link safety, Knowledge Base tone rules, literal cross-links and Markdown code fences.

Current expected corpus:

- 63 Research entries
- 7 Knowledge Base entries
- 1 published Article

The script is intentionally a fast repository sanity check. `npm run build` remains the authoritative Astro build check.
