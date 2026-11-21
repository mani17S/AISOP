/**
 * AISOP pre-launch gate. Run with: npm run prelaunch
 *
 * Fails (exit 1) while any launch requirement is unmet. It checks files only; it does not deploy anything.
 * Requirements come from the owner's launch rules: no purple gradients, pill buttons, fake reviews or metrics,
 * vague hero text, emoji icons, em dashes, scroll or cursor animation, AI-made-with tags or AI slop images;
 * and a custom domain, favicon, privacy policy and terms page must exist before launch.
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const SRC = join(ROOT, 'src');
const results = [];
const check = (name, ok, detail = '') => results.push({ name, ok, detail });

const walk = (dir) =>
  readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
const srcFiles = walk(SRC).filter((f) => ['.ts', '.tsx', '.css'].includes(extname(f)));
const html = readFileSync(join(ROOT, 'index.html'), 'utf8');
const read = (f) => readFileSync(f, 'utf8');

const scan = (label, test) => {
  const hits = [];
  for (const f of [...srcFiles, join(ROOT, 'index.html')]) {
    read(f).split(/\r?\n/).forEach((line, i) => {
      if (test(line, f)) hits.push(`${f.replace(ROOT, '')}:${i + 1}`);
    });
  }
  check(label, hits.length === 0, hits.slice(0, 5).join(', '));
};

// Banned visual and copy patterns
scan('no em dashes', (l) => l.includes('—'));
scan('no emoji or dingbat icons', (l) => /[\u{1F300}-\u{1FAFF}☀-➿⭐]/u.test(l));
scan('no gradients or glass blur in code', (l, f) => /gradient|backdrop-filter/i.test(l) && !/^\s*(\/\/|\*|\/\*)/.test(l.trim()));
scan('no pill radius above 8px (px values)', (l, f) => f.endsWith('.css') && /border-radius:\s*(9|[1-9]\d+)px/.test(l));
scan('no scroll or cursor effects', (l) => /IntersectionObserver|addEventListener\(\s*['"](scroll|mousemove)|cursor:\s*url|parallax/i.test(l));
scan('no "made with AI" or hype tags', (l) => /made with (ai|love)|powered by (ai|magic)|ai-powered|supercharge|revolutioni|next-generation|unleash/i.test(l));
scan('no fake social proof or counters', (l) => /trusted by|testimonial|fortune 500|\d{1,3},\d{3}\+|customers? (served|protected)/i.test(l));
scan('no non-spinner animations', (l, f) => f.endsWith('.css') && /@keyframes\s+(?!aisop-spin)/.test(l));

// Required assets and pages
check('favicon file exists', existsSync(join(ROOT, 'public', 'favicon.svg')));
check('favicon linked in index.html', /rel="icon"[^>]*favicon/.test(html));
check('privacy page exists', existsSync(join(SRC, 'pages', 'Legal.tsx')) && /PrivacyPolicy/.test(read(join(SRC, 'App.tsx'))));
check('terms page exists', /TermsOfService/.test(read(join(SRC, 'App.tsx'))));
check('privacy and terms linked in the UI', /href="\/privacy"/.test(read(join(SRC, 'App.tsx'))) && /href="\/terms"/.test(read(join(SRC, 'App.tsx'))));

// Owner-supplied facts that must never be invented
const op = read(join(SRC, 'legal', 'operator.ts'));
for (const field of ['name', 'contactUrl', 'effectiveDate']) {
  const m = op.match(new RegExp(`${field}:\\s*'([^']*)'`));
  check(`operator.${field} filled in`, Boolean(m && m[1].trim()), 'src/legal/operator.ts');
}
check(
  'governing law stated or the Terms say none is chosen',
  /jurisdiction:\s*'[^']+'/.test(op) || /No governing law has been chosen/.test(read(join(SRC, 'pages', 'Legal.tsx'))),
);

// Custom domain: recorded by the owner once DNS is connected
const domainFile = join(ROOT, '..', 'deploy', 'DOMAIN.txt');
const domain = existsSync(domainFile) ? read(domainFile).trim() : '';
check('custom domain recorded in deploy/DOMAIN.txt', /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain), domain || 'missing');
const dist = join(ROOT, 'dist', 'index.html');
const csp = existsSync(dist) ? (read(dist).match(/connect-src ([^;]*);/) || [])[1] || '' : '';
check(
  'built CSP connect-src allows an https API origin (build with VITE_API_BASE_URL)',
  /https:\/\//.test(csp),
  existsSync(dist) ? `dist connect-src: ${csp}` : 'no dist build',
);

for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.ok || !r.detail ? '' : `  (${r.detail})`}`);
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
