#!/usr/bin/env node
// Generates the static brand assets from the same geometry the UI uses:
//   ui/public/panoptic.svg        favicon / in-app static mark
//   src-tauri/app-icon.svg        source for `tauri icon` (all platform icons)
//   docs/brand/wordmark-dark.svg  README header (dark backgrounds)
//   docs/brand/wordmark-light.svg README header (light backgrounds)
// Run: node scripts/generate-brand.mjs
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// Mirror of ui/src/brand/mark.ts (kept dependency-free for Node).
const CELLS = 12;
const LIT = 1;
const G = { cx: 32, cy: 32, outer: 29, inner: 19.5, gapDeg: 6 };
const rad = (d) => (d * Math.PI) / 180;
const r2 = (n) => Math.round(n * 100) / 100;
const polar = (r, d) => [r2(G.cx + r * Math.sin(rad(d))), r2(G.cy - r * Math.cos(rad(d)))];
const span = (i) => {
  const step = 360 / CELLS;
  return [i * step - step / 2 + G.gapDeg / 2, i * step + step / 2 - G.gapDeg / 2];
};
const cell = (i) => {
  const [a0, a1] = span(i);
  const [x0, y0] = polar(G.outer, a0);
  const [x1, y1] = polar(G.outer, a1);
  const [x2, y2] = polar(G.inner, a1);
  const [x3, y3] = polar(G.inner, a0);
  return `M${x0} ${y0}A${G.outer} ${G.outer} 0 0 1 ${x1} ${y1}L${x2} ${y2}A${G.inner} ${G.inner} 0 0 0 ${x3} ${y3}Z`;
};
const beam = (i) => {
  const [a0, a1] = span(i);
  const [x1, y1] = polar(G.inner - 0.6, a0 + 3);
  const [x2, y2] = polar(G.inner - 0.6, a1 - 3);
  return `M${G.cx} ${G.cy}L${x1} ${y1}L${x2} ${y2}Z`;
};

const INK = '#090B10';
const LIME = '#C8F135';
const TEAL = '#2DE2C5';

function markGroup({ cellFill, ringStroke }) {
  const cells = Array.from({ length: CELLS }, (_, i) => `<path d="${cell(i)}" fill="${i === LIT ? LIME : cellFill}"/>`).join('');
  return `
    <path d="${beam(LIT)}" fill="url(#beam)"/>
    ${cells}
    <circle cx="32" cy="32" r="11.2" fill="none" stroke="${ringStroke}" stroke-width="1.4"/>
    <circle cx="32" cy="32" r="5.6" fill="${LIME}"/>
    <circle cx="32" cy="32" r="2.1" fill="${INK}"/>`;
}

const defs = `<defs>
    <linearGradient id="beam" gradientUnits="userSpaceOnUse" x1="32" y1="32" x2="${polar(G.inner, 30)[0]}" y2="${polar(G.inner, 30)[1]}">
      <stop offset="0" stop-color="${LIME}" stop-opacity="0.05"/>
      <stop offset="1" stop-color="${LIME}" stop-opacity="0.75"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.62" cy="0.3" r="0.8">
      <stop offset="0" stop-color="${LIME}" stop-opacity="0.16"/>
      <stop offset="0.55" stop-color="${TEAL}" stop-opacity="0.04"/>
      <stop offset="1" stop-color="${INK}" stop-opacity="0"/>
    </radialGradient>
  </defs>`;

// Favicon / static mark: transparent, works on dark and light.
const favicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  ${defs}
  <rect width="64" height="64" rx="15" fill="${INK}"/>
  <g transform="translate(5.4 5.4) scale(0.83)">${markGroup({ cellFill: '#2B3346', ringStroke: '#3B4560' })}</g>
</svg>
`;

// App icon: squircle with soft beacon glow.
const appIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024">
  ${defs.replace('</defs>', `<linearGradient id="edge" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#FFFFFF" stop-opacity="0.10"/><stop offset="1" stop-color="#FFFFFF" stop-opacity="0"/></linearGradient></defs>`)}
  <rect x="32" y="32" width="960" height="960" rx="224" fill="${INK}"/>
  <rect x="32" y="32" width="960" height="960" rx="224" fill="url(#glow)"/>
  <rect x="33" y="33" width="958" height="958" rx="223" fill="none" stroke="url(#edge)" stroke-width="3"/>
  <g transform="translate(152 152) scale(11.25)">${markGroup({ cellFill: '#262E40', ringStroke: '#39435A' })}</g>
</svg>
`;

function wordmark(theme) {
  const fg = theme === 'dark' ? '#E9ECF2' : '#0E1118';
  const sub = theme === 'dark' ? '#8C94A8' : '#545B68';
  const cellFill = theme === 'dark' ? '#2B3346' : '#D9DDD2';
  const ring = theme === 'dark' ? '#3B4560' : '#B9BFB0';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 520 120">
  ${defs}
  <g transform="translate(8 8) scale(1.62)">${markGroup({ cellFill, ringStroke: ring })}</g>
  <text x="132" y="68" fill="${fg}" font-family="'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif" font-size="54" font-weight="700" letter-spacing="7">PANOPTIC</text>
  <text x="134" y="98" fill="${sub}" font-family="'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif" font-size="17" letter-spacing="3.2">SEE EVERY LAYER</text>
</svg>
`;
}

const out = [
  ['ui/public/panoptic.svg', favicon],
  ['src-tauri/app-icon.svg', appIcon],
  ['docs/brand/wordmark-dark.svg', wordmark('dark')],
  ['docs/brand/wordmark-light.svg', wordmark('light')],
  ['docs/brand/mark.svg', favicon],
];
for (const [rel, svg] of out) {
  const p = join(root, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, svg);
  console.log(`wrote ${rel}`);
}
