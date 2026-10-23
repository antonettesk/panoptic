# Building Panoptic

## Prerequisites

| | Windows | Linux (Debian/Ubuntu) |
|---|---|---|
| Rust | stable via rustup, **MSVC** toolchain + Visual Studio Build Tools (C++ workload) | stable via rustup |
| Node.js | 18 or later | 18 or later |
| System libs | WebView2 (preinstalled on Windows 10/11) | `libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf build-essential` |

## Commands

Install the dependencies:

```bash
npm install
```

Run the desktop app with hot reload. This first builds the CLI sidecar into `src-tauri/binaries/`:

```bash
npm run dev
```

Build the release installers into `target/release/bundle/`:

```bash
npm run build
```

Build only the headless scanner:

```bash
cargo build --release -p panoptic-cli
```

`npm run build` runs `scripts/prepare-sidecar.mjs`. That script compiles `panoptic-cli` and copies it to `src-tauri/binaries/panoptic-cli-<target-triple>[.exe]`, where Tauri's `externalBin` packaging expects it. The installer places it next to the GUI executable, and scheduled scans use it from there.

> `cargo clippy` / `cargo build -p panoptic` on a fresh checkout needs the sidecar first. Run `npm run sidecar` once.

## Windows GNU toolchain (optional)

The `x86_64-pc-windows-gnu` toolchain works, but it needs a complete mingw-w64. For example, [WinLibs](https://winlibs.com) (`winget install BrechtSanders.WinLibs.POSIX.UCRT`) must be on `PATH`, because newer `windows-sys` versions use raw-dylib, which needs `dlltool` and `as`. MSVC is recommended for release builds.

## Offline installers

`tauri.conf.json` sets `webviewInstallMode: offlineInstaller`, which embeds the WebView2 runtime (about 130 MB). The Windows installer therefore works on air-gapped machines. If size matters more, switch to `embedBootstrapper` or `downloadBootstrapper`.

## Reproducibility

- `Cargo.lock` and `package-lock.json` are committed.
- The release profile uses `lto = true`, `codegen-units = 1` and `strip = true`.
- CI builds release artefacts from tags only (see `.github/workflows/build.yml`).
