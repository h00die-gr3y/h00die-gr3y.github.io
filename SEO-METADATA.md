# v2.15 — SEO, feeds and redirect cleanup

This release adds the technical discovery layer around the existing Astro content without changing the research corpus.

## Metadata

`BaseLayout.astro` now emits:

- canonical URLs
- Open Graph metadata
- Twitter summary metadata
- robots directives
- RSS and sitemap discovery links
- JSON-LD structured data
- article publication/revision metadata where dates exist
- the h00die-gr3y GitHub profile as the public identity link

Research and Knowledge Base pages use `TechArticle` structured data. Long-form Articles use `Article`, and About uses `ProfilePage`.

## Discovery endpoints

- `/sitemap.xml` — canonical public pages only; legacy redirects are deliberately excluded
- `/rss.xml` — 30 most recently revised/published Research and Article entries
- `/robots.txt` — allows crawling and advertises the sitemap
- `/404.html` — custom not-found page for static hosting

No additional npm package is required for these endpoints.

## Redirect cleanup

Legacy route pages now share one redirect component. Each redirect page:

- points its canonical URL at the destination
- is marked `noindex,follow`
- uses a static meta-refresh redirect
- provides a visible destination link as fallback

Likely Jekyll date-style URLs for the three old posts are also covered in both directory and `.html` form.

## Social image

The existing h00die-gr3y square logo is published at:

`/images/site/h00die-gr3y-social.png`

It is used as the default social-preview image. Smaller favicon and Apple touch-icon variants are included alongside it.
