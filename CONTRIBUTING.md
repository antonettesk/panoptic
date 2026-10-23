# Contributing to Panoptic

Thanks for helping make threat hunting more accessible. This guide covers how to get set up, what we expect from changes, and how reviews work.

By participating you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Detections.** New persistence mechanisms, heuristics or cross-layer checks. See [docs/DETECTIONS.md](docs/DETECTIONS.md).
- **False-positive reports.** These are just as valuable as new detections. Include the finding JSON (use **Copy → JSON** in the app) and your OS version.
- **Translations.** See [docs/TRANSLATING.md](docs/TRANSLATING.md).
- **Docs, UX and accessibility.** Anything that makes Panoptic easier to understand and use.

## Development setup

You need Rust (stable, via [rustup](https://rustup.rs)) and Node.js 18 or later. On Linux you also need the WebKitGTK packages listed in the [README](README.md#build-from-source).

Install the dependencies:

```bash
npm install
```

Start the desktop app with hot reload (this also builds the CLI sidecar):

```bash
npm run dev
```

Run the UI on its own in a browser, with simulated data:

```bash
npm run dev -w ui
```

Run every test (Rust and UI):

```bash
npm test
```

Run the same lints as CI (clippy with `-D warnings`, plus a TypeScript type check):

```bash
npm run lint
```

> **Linux testing from Windows/macOS:** the Linux engine needs a real `/proc`. A container works well:
> `docker run --rm -v "$PWD:/src" -w /src rust:1-bookworm cargo test -p panoptic-core`

## Change guidelines

- **Every detection needs a test.**
  - Pure logic (parsers, heuristics, classification) gets a unit test next to the code.
  - Live-system behaviour gets a test that runs safely on CI runners.
- **Every finding must be explainable.** It needs evidence strings, a MITRE ATT&CK technique and a recommendation.
- **Precision over recall.** Before proposing a rule, run it against a clean, real machine. A rule that fires on a stock Windows or Ubuntu install needs to be narrowed, or downgraded to Low or Info.
- **Never write detection test code that hides or evades.** Exercise the analysis logic through `TruthEngine` fakes (see `scanner.rs` tests) instead of building hiding techniques.
- **Read-only.** Scanning must never modify the system. Anything that changes state must be an explicit, confirmed user action.
- **Offline.** No network calls beyond loopback/local-interface checks. No telemetry, ever.
- **UI strings go through i18n.** Add every new key to `ui/src/i18n/locales/en.ts` and all other locales. The catalog test fails if a key or placeholder is missing.
- Run `cargo fmt` and keep `npm run lint` clean.

## Commits and pull requests

- Use clear, imperative commit messages, for example `Add udev RUN+= persistence check`. We follow [Conventional Commits](https://www.conventionalcommits.org/) where practical (`feat:`, `fix:`, `docs:` and so on).
- Keep pull requests focused. Fill in the PR template, including the false-positive testing you did.
- CI must be green before review. A maintainer will review within a few days.
- By submitting a contribution, you agree to license it under the [GNU Affero General Public License v3.0](LICENSE) (`AGPL-3.0-only`), the project's license. Only contribute code you have the right to license this way.
- New dependencies must use an AGPL-3.0-compatible license, such as MIT, Apache-2.0, BSD, ISC, MPL-2.0, LGPL, GPL-3.0 or OFL for fonts. Mention the license in your PR.

## Release process (maintainers)

1. Update [CHANGELOG.md](CHANGELOG.md) and bump the version in `Cargo.toml`, `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json` and both `package.json` files.
2. Tag `vX.Y.Z`. CI builds and uploads the Windows and Linux installers.
3. Publish the GitHub release with the changelog section and SHA-256 checksums.
