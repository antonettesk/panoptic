# Architecture

Panoptic is a Rust workspace with three crates and a React front end.

```
┌──────────────────────────── Desktop app (Tauri v2) ────────────────────────────┐
│  ui/ (React + TS + Tailwind, i18n)  ──IPC──►  src-tauri/src/commands.rs          │
└───────────────────────────────────────────────┬──────────────────────────────────┘
                                                │ uses
┌──────────────────── crates/panoptic-core (library) ──────────────────────────────┐
│ scanner.rs   orchestrates stages in parallel, confirms, scores, annotates        │
│ engine/                                                                          │
│   traits.rs      TruthEngine trait: one method per OS layer                      │
│   linux_engine.rs / windows_engine.rs   raw observations only                    │
│   anomaly.rs     pure comparison logic (classify → confirm → findings)           │
│   heuristics.rs  command / path / port rules                                     │
│   portprobe.rs   kernel bind() truth + connect() confirmation                    │
│ asff.rs  baseline.rs  config.rs  report.rs  schedule.rs  settings.rs             │
└───────────────────────────────────────────────┬──────────────────────────────────┘
                                                │ uses
                     crates/panoptic-cli  (headless scanner, bundled as sidecar)
```

## Design principles

1. **Engines observe; the analyzer judges.** Platform engines only report what a layer says. All comparison logic lives in `anomaly.rs` and is pure, so it can be unit-tested with fake engines (see the `FakeEngine` in `scanner.rs`).
2. **Confirm before accusing.** Every candidate discrepancy is re-checked several times (`confirm_rounds`) against a fresh enumeration and a liveness probe. This removes races where a process starts, or a socket closes, between snapshots.
3. **Fail loudly, never silently clean.** Each stage returns a `StageStatus`. A stage that failed (for example, missing privileges) is shown as failed. It is never presented as "nothing found".
4. **Explainable findings.** Every `Finding` has a stable ID (FNV-1a of category + subject), evidence strings, an ATT&CK technique and a recommendation.
5. **Read-only and offline.**

## Scan pipeline

```
          ┌── processes: API view → syscall view → brute-force → classify → confirm ──┐
start ────┼── network:   socket table → bind() probe ×4 protocols → confirm → connect()┼──► correlate
          └── persistence → kernel modules → integrity checks ───────────────────────┘     │
                                                                                            ▼
                    heuristics → de-duplicate → hash evidence → suppress → score → ScanReport
```

The three branches run in parallel (`std::thread::scope`). Brute-force loops are split across worker threads and check a cancellation token.

## Ghost classification

| API view | Syscall view | Brute-force | Verdict |
|:---:|:---:|:---:|---|
| ✓ | ✓ | ✓ | Verified |
| ✗ | ✓ | ✓ | **User-mode hook** (LD_PRELOAD / IAT hooks), T1574.006 |
| ✗ | ✗ | ✓ | **Kernel-hidden** (getdents hook / DKOM), T1014 |

On Windows without elevation, `OpenProcess` can return *access denied*. In that case Panoptic cannot tell a hidden process from a zombie (an exited process whose handle is still held), so such results are downgraded to **Low**, labelled *unverified*, and marked for an elevated rescan.

## Data and storage

| File | Location | Purpose |
|---|---|---|
| `settings.json` | app data dir | onboarding state, language, theme, opt-ins |
| `suppressions.json` | app data dir | accepted finding IDs and path patterns |
| `baseline.json` | app data dir | known-good snapshot for drift detection |
| `history/<scan_id>.json` | app data dir | last 25 full reports (GUI and scheduled scans) |

All writes are atomic: write to a temporary file, then rename.

## Front end

- `settings.tsx`: persisted settings context with optimistic updates and rollback.
- `i18n/`: typed catalogs. A test enforces that every locale has every key and identical placeholders. RTL is handled with Tailwind logical properties (`ms-`, `pe-`, `start-`, `end-`).
- `mock.ts`: a browser-only demo backend, so the UI can be developed and reviewed without the native shell.
