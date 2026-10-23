# Panoptic brand

## The mark

A **panopticon floor plan**: twelve cells arranged around a central watchtower. One cell is lit and joined to the tower by a sightline. It shows what the product does: it watches every cell and spots the one that doesn't fit.

<img src="brand/mark.svg" width="96" alt="Panoptic mark" />

The mark is generated from a single geometry source:

- `ui/src/brand/mark.ts` holds the geometry, shared by the app, the cell gauge and the generator.
- `scripts/generate-brand.mjs` writes the favicon, the app-icon source (`src-tauri/app-icon.svg`) and the README wordmarks.

Regenerate the assets:

```bash
node scripts/generate-brand.mjs
```

Then rebuild the platform icons from the new source:

```bash
npx tauri icon src-tauri/app-icon.svg -o src-tauri/icons
```

**Signature uses**

- **Watchtower:** while a scan runs, the sightline sweeps around the tower (sidebar mark and splash screen).
- **Cell gauge:** the risk score lights up cells of the mark, clockwise from the top, coloured by risk level.
- **Panopticon pattern:** concentric galleries and radial walls at about 7% opacity, used behind hero surfaces (welcome, onboarding rail).

## Palette: "Ink & Beacon"

| Token | Dark | Light | Use |
|---|---|---|---|
| Ink | `#090B10` | `#F5F6F1` (paper) | Backgrounds; the onboarding rail is always ink |
| Beacon | `#C8F135` | `#4D7C0F` | Brand accents, the lit cell, focus rings, active nav |
| Call to action | Beacon on ink | Ink with beacon text | Primary buttons |
| Signal teal | `#2DE2C5` | `#0D9488` | Verified / healthy states |
| Critical | `#FF4D5E` | `#DC2640` | Severity only, never decoration |

Severity colours are reserved for findings. The beacon is never used to mean "danger".

## Typography

All typefaces are bundled with the app (via Fontsource), so they work fully offline.

| Role | Typeface |
|---|---|
| Display, headings, wordmark, numbers | **Space Grotesk** |
| Interface | **Inter** |
| Data, paths, hashes, commands | **JetBrains Mono** |

The wordmark is `PANOPTIC` in Space Grotesk Bold, set with wide tracking (0.22em). The tagline is **See every layer**.

## Voice

Calm, precise and evidence-first. Say what was observed and why it matters. Never sensationalise, and always pair a verdict with a next step.
