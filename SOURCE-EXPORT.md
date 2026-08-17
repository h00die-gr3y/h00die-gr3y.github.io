# Legacy source-export scope

The v2.12 inventory identified 17 candidate legacy pages/posts. The migration review reduced the source-material export to seven files whose bodies are still needed for editorial migration.

Included:

1. `_pages/ad-domain-attack.md`
2. `_pages/tips-and-tricks.md`
3. `_pages/module-development.md`
4. `_posts/2024-08-26-howto-uart-shell.md`
5. `_pages/iot-uart-shell.md`
6. `_pages/references.md`
7. `_pages/log4shell.md`

Not exported here:

- legacy index/placeholder/about/blog/disclaimer pages that are not Knowledge Base source material;
- GeoServer and OpenMediaVault exploit posts already represented by migrated Research pages;
- the old zero-days grouping page and initial welcome post.

The exporter is read-only with respect to the legacy repository and writes only into the Astro project's `migration/` directory.
