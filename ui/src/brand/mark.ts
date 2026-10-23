// Panoptic mark geometry: a panopticon floor plan. Twelve cells encircle a
// central watchtower; one cell is "lit" and joined to the tower by a sightline.
// Shared by the <Mark> component, the cell risk gauge and scripts/generate-brand.mjs.

export const CELLS = 12;
export const LIT_CELL = 1;

export interface MarkGeometry {
  cx: number;
  cy: number;
  outer: number;
  inner: number;
  gapDeg: number;
}

export const MARK: MarkGeometry = { cx: 32, cy: 32, outer: 29, inner: 19.5, gapDeg: 6 };

const rad = (deg: number) => (deg * Math.PI) / 180;
const round = (n: number) => Math.round(n * 100) / 100;

/** Point at radius `r`, angle `deg` (0° = 12 o'clock, clockwise). */
export function polar(g: MarkGeometry, r: number, deg: number): [number, number] {
  return [round(g.cx + r * Math.sin(rad(deg))), round(g.cy - r * Math.cos(rad(deg)))];
}

/** Angular span of cell `i` (centred on i × 30°). */
export function cellSpan(i: number, g: MarkGeometry = MARK): [number, number] {
  const step = 360 / CELLS;
  const centre = i * step;
  return [centre - step / 2 + g.gapDeg / 2, centre + step / 2 - g.gapDeg / 2];
}

/** SVG path for an annular sector (one cell). */
export function cellPath(i: number, g: MarkGeometry = MARK, outer = g.outer, inner = g.inner): string {
  const [a0, a1] = cellSpan(i, g);
  const [x0, y0] = polar(g, outer, a0);
  const [x1, y1] = polar(g, outer, a1);
  const [x2, y2] = polar(g, inner, a1);
  const [x3, y3] = polar(g, inner, a0);
  return `M${x0} ${y0}A${outer} ${outer} 0 0 1 ${x1} ${y1}L${x2} ${y2}A${inner} ${inner} 0 0 0 ${x3} ${y3}Z`;
}

/** The sightline: a wedge from the tower to the inner edge of a cell. */
export function beamPath(i: number, g: MarkGeometry = MARK): string {
  const [a0, a1] = cellSpan(i, g);
  const [x1, y1] = polar(g, g.inner - 0.6, a0 + 3);
  const [x2, y2] = polar(g, g.inner - 0.6, a1 - 3);
  return `M${g.cx} ${g.cy}L${x1} ${y1}L${x2} ${y2}Z`;
}
