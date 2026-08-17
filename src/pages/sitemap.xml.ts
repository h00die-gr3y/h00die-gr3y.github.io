import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';

const escapeXml = (value: string) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&apos;');

const maxDate = (values: string[]) => values.filter(Boolean).sort().at(-1);

export const GET: APIRoute = async ({ site }) => {
  const base = site ?? new URL('https://h00die-gr3y.github.io');
  const research = await getCollection('research');
  const articles = (await getCollection('articles')).filter((entry) => entry.data.status === 'published');
  const knowledge = (await getCollection('knowledgeBase')).filter((entry) => entry.data.status === 'published');

  const latestResearch = maxDate(research.map((entry) => entry.data.revised || entry.data.published));
  const latestAdvisory = maxDate(research.flatMap((entry) => entry.data.disclosure?.advisories.map((item) => item.published ?? '') ?? []));
  const latestArticle = maxDate(articles.map((entry) => entry.data.revised || entry.data.published));
  const latestEditorial = maxDate([latestResearch ?? '', latestArticle ?? '']);

  const urls: Array<{ path: string; lastmod?: string }> = [
    { path: '/', lastmod: latestEditorial },
    { path: '/research/', lastmod: latestResearch },
    { path: '/advisories/', lastmod: latestAdvisory || latestResearch },
    { path: '/cves/', lastmod: latestResearch },
    { path: '/exploits/', lastmod: latestResearch },
    { path: '/articles/', lastmod: latestArticle },
    { path: '/knowledge-base/' },
    { path: '/about/' },
    { path: '/disclaimer/' },
    ...research.map((entry) => ({
      path: `/research/${entry.id}/`,
      lastmod: entry.data.revised || entry.data.published,
    })),
    ...articles.map((entry) => ({
      path: `/articles/${entry.id}/`,
      lastmod: entry.data.revised || entry.data.published,
    })),
    ...knowledge.map((entry) => ({ path: `/knowledge-base/${entry.id}/` })),
  ];

  const unique = [...new Map(urls.map((entry) => [entry.path, entry])).values()];
  const body = unique.map(({ path, lastmod }) => {
    const location = escapeXml(new URL(path, base).toString());
    return `  <url>\n    <loc>${location}</loc>${lastmod ? `\n    <lastmod>${escapeXml(lastmod)}</lastmod>` : ''}\n  </url>`;
  }).join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${body}\n</urlset>\n`;

  return new Response(xml, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};
