import { getCollection } from 'astro:content';
import type { APIRoute } from 'astro';

const escapeXml = (value: string) => value
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&apos;');

const dateValue = (value: string) => {
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? new Date(0) : date;
};

export const GET: APIRoute = async ({ site }) => {
  const base = site ?? new URL('https://h00die-gr3y.github.io');
  const feedUrl = new URL('/rss.xml', base).toString();

  const research = (await getCollection('research')).map((entry) => ({
    title: entry.data.title,
    description: entry.data.description,
    path: `/research/${entry.id}/`,
    published: entry.data.published,
    revised: entry.data.revised,
    category: entry.data.researchType === 'original-research' ? 'Original Research' : 'Technical Analysis',
  }));

  const articles = (await getCollection('articles'))
    .filter((entry) => entry.data.status === 'published')
    .map((entry) => ({
      title: entry.data.title,
      description: entry.data.description,
      path: `/articles/${entry.id}/`,
      published: entry.data.published,
      revised: entry.data.revised,
      category: 'Article',
    }));

  const items = [...research, ...articles]
    .sort((a, b) => dateValue(b.revised || b.published).getTime() - dateValue(a.revised || a.published).getTime())
    .slice(0, 30);

  const latest = items[0]?.revised || items[0]?.published || '2026-08-17';
  const itemXml = items.map((item) => {
    const link = new URL(item.path, base).toString();
    return `    <item>\n      <title>${escapeXml(item.title)}</title>\n      <link>${escapeXml(link)}</link>\n      <guid isPermaLink="true">${escapeXml(link)}</guid>\n      <pubDate>${dateValue(item.published).toUTCString()}</pubDate>\n      <category>${escapeXml(item.category)}</category>\n      <description>${escapeXml(item.description)}</description>\n    </item>`;
  }).join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n  <channel>\n    <title>h00die-gr3y — Research Feed</title>\n    <link>${escapeXml(new URL('/', base).toString())}</link>\n    <description>Independent security research, vulnerability analysis, exploit development and technical articles by h00die-gr3y.</description>\n    <language>en</language>\n    <lastBuildDate>${dateValue(latest).toUTCString()}</lastBuildDate>\n    <atom:link href="${escapeXml(feedUrl)}" rel="self" type="application/rss+xml" />\n${itemXml}\n  </channel>\n</rss>\n`;

  return new Response(xml, {
    headers: { 'Content-Type': 'application/rss+xml; charset=utf-8' },
  });
};
