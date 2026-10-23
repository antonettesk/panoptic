import { useId } from 'react';
import { CELLS, LIT_CELL, MARK, beamPath, cellPath, polar } from './mark';

/**
 * The Panoptic mark: a panopticon floor plan. Twelve cells around a central
 * watchtower, one lit and joined to the tower by a sightline.
 *  - `tile`     ink squircle background (app-icon style, works on any theme)
 *  - `scanning` the sightline sweeps around the tower
 */
export function Mark({ size = 32, tile = false, scanning = false, title }: { size?: number; tile?: boolean; scanning?: boolean; title?: string }) {
  const id = useId().replace(/:/g, '');
  const [bx, by] = polar(MARK, MARK.inner, LIT_CELL * 30);
  const cellFill = tile ? '#2B3346' : 'rgb(var(--cell))';
  const ring = tile ? '#3B4560' : 'rgb(var(--line))';
  const lime = tile ? '#C8F135' : 'rgb(var(--brand))';
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role={title ? 'img' : undefined} aria-hidden={title ? undefined : true} aria-label={title} style={{ direction: 'ltr', flexShrink: 0 }}>
      <defs>
        <linearGradient id={`b${id}`} gradientUnits="userSpaceOnUse" x1="32" y1="32" x2={bx} y2={by}>
          <stop offset="0" stopColor={lime} stopOpacity="0.05" />
          <stop offset="1" stopColor={lime} stopOpacity="0.75" />
        </linearGradient>
      </defs>
      {tile && <rect width="64" height="64" rx="15" fill="#090B10" />}
      <g transform={tile ? 'translate(5.4 5.4) scale(0.83)' : undefined}>
        <g className={scanning ? 'watching' : undefined}>
          <path d={beamPath(LIT_CELL)} fill={`url(#b${id})`} />
        </g>
        {Array.from({ length: CELLS }, (_, i) => (
          <path key={i} d={cellPath(i)} fill={i === LIT_CELL && !scanning ? lime : cellFill} style={{ transition: 'fill 300ms' }} />
        ))}
        <circle cx="32" cy="32" r="11.2" fill="none" stroke={ring} strokeWidth="1.4" />
        <circle cx="32" cy="32" r="5.6" fill={lime} />
        <circle cx="32" cy="32" r="2.1" fill="#090B10" />
      </g>
    </svg>
  );
}

export function Wordmark({ size = 15, tagline }: { size?: number; tagline?: string }) {
  return (
    <span className="flex min-w-0 flex-col leading-none">
      <span className="wordmark text-fg" style={{ fontSize: size }}>
        Panoptic
      </span>
      {tagline && <span className="mt-1 truncate font-display text-[10px] uppercase tracking-[0.18em] text-subtle">{tagline}</span>}
    </span>
  );
}

/**
 * Decorative panopticon plan: concentric galleries and radial cell walls.
 * Purely visual; positioned by the caller.
 */
export function PanopticonPattern({ className = '', rings = 6, spokes = 24 }: { className?: string; rings?: number; spokes?: number }) {
  const r = 50;
  return (
    <svg viewBox="0 0 100 100" className={`pointer-events-none select-none ${className}`} aria-hidden="true" style={{ direction: 'ltr' }}>
      <g fill="none" stroke="rgb(var(--fg))" strokeOpacity="0.07" strokeWidth="0.18">
        {Array.from({ length: rings }, (_, i) => (
          <circle key={i} cx="50" cy="50" r={r * ((i + 1) / rings)} />
        ))}
        {Array.from({ length: spokes }, (_, i) => {
          const a = (i * 2 * Math.PI) / spokes;
          return <line key={i} x1={50 + (r / rings) * Math.sin(a)} y1={50 - (r / rings) * Math.cos(a)} x2={50 + r * Math.sin(a)} y2={50 - r * Math.cos(a)} />;
        })}
      </g>
    </svg>
  );
}

/**
 * Risk as the brand mark: the score lights up cells clockwise from the top.
 * Colour follows the risk level; the tower carries the number.
 */
export function CellGauge({ score, color, label, size = 196 }: { score: number; color: string; label: string; size?: number }) {
  const lit = score <= 0 ? 0 : Math.max(1, Math.round((Math.min(100, score) / 100) * CELLS));
  const g = { ...MARK, outer: 30, inner: 22.5, gapDeg: 5 };
  return (
    <div className="flex flex-col items-center gap-3" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={score} aria-label={label}>
      <div className="relative" style={{ width: size, height: size }}>
        <div className="beacon-glow absolute inset-0 rounded-full opacity-60" />
        <svg viewBox="0 0 64 64" width={size} height={size} className="relative" style={{ direction: 'ltr' }}>
          {Array.from({ length: CELLS }, (_, i) => (
            <path
              key={`${i}-${lit}`}
              d={cellPath(i, g)}
              className={i < lit ? 'cell-on' : undefined}
              style={{ animationDelay: `${i * 45}ms` }}
              fill={i < lit ? color : 'rgb(var(--cell))'}
              fillOpacity={i < lit ? 1 : 0.55}
            />
          ))}
          <circle cx="32" cy="32" r="18.5" fill="rgb(var(--surface))" stroke="rgb(var(--line))" strokeWidth="0.6" />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-display font-semibold tabular-nums tracking-tight" style={{ fontSize: size * (score >= 100 ? 0.17 : 0.2) }}>
            {score}
          </span>
          <span className="mt-0.5 font-display text-[10px] uppercase tracking-[0.2em] text-subtle">/ 100</span>
        </div>
      </div>
      <span className="rounded-full px-3 py-1 font-display text-xs font-semibold uppercase tracking-[0.14em]" style={{ color, background: `color-mix(in srgb, ${color} 13%, transparent)` }}>
        {label}
      </span>
    </div>
  );
}
