/** @type {import('tailwindcss').Config} */
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: token('bg'),
        surface: token('surface'),
        raised: token('raised'),
        line: token('line'),
        fg: token('fg'),
        muted: token('muted'),
        subtle: token('subtle'),
        brand: token('brand'),
        'brand-fg': token('brand-fg'),
        cta: token('cta'),
        'cta-fg': token('cta-fg'),
        ink: token('ink'),
        cell: token('cell'),
        accent: token('accent'),
        danger: token('danger'),
        warn: token('warn'),
        caution: token('caution'),
        info: token('info'),
        ok: token('ok'),
      },
      fontFamily: {
        sans: ['"Inter Variable"', 'Inter', '"Segoe UI Variable Text"', '"Segoe UI"', 'system-ui', '-apple-system', '"Noto Sans"', '"Noto Sans Arabic"', '"Noto Sans Devanagari"', '"Noto Sans CJK SC"', '"Hiragino Sans"', '"Yu Gothic UI"', 'sans-serif'],
        display: ['"Space Grotesk Variable"', '"Space Grotesk"', '"Inter Variable"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono Variable"', '"JetBrains Mono"', '"Cascadia Code"', 'ui-monospace', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 0 0 rgb(var(--line) / 0.6), 0 8px 24px -12px rgb(0 0 0 / 0.35)',
        pop: '0 20px 60px -15px rgb(0 0 0 / 0.55)',
      },
      keyframes: {
        'fade-in': { from: { opacity: 0, transform: 'translateY(4px)' }, to: { opacity: 1, transform: 'none' } },
      },
      animation: { 'fade-in': 'fade-in 180ms ease-out' },
    },
  },
  plugins: [],
};
