//! `panoptic-cli` — headless Cross-Layer Truth scanner.
//!
//! Exit codes: 0 = clean (nothing at/above --fail-on), 1 = findings at/above
//! --fail-on, 2 = error, 3 = scan cancelled/partial.

use clap::{Parser, Subcommand};
use panoptic_core::asff::{self, AsffTarget};
use panoptic_core::{report, Baseline, CancelToken, ProcessAction, ScanOptions, Scanner, Severity, Suppressions};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "panoptic-cli",
    version,
    about = "Panoptic cross-layer threat hunting scanner",
    after_help = "Copyright (C) 2026 Panoptic Contributors.\nThis program comes with ABSOLUTELY NO WARRANTY. It is free software, and you are\nwelcome to redistribute it under the terms of the GNU Affero General Public\nLicense v3.0 (AGPL-3.0-only). See LICENSE or https://www.gnu.org/licenses/agpl-3.0."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

// Parsed once at startup; boxing the large `Scan` variant buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Cmd {
    /// Run a full cross-layer scan.
    Scan {
        /// Write the full JSON report here.
        #[arg(long)]
        json: Option<PathBuf>,
        /// Write a self-contained HTML report here.
        #[arg(long)]
        html: Option<PathBuf>,
        /// Write findings as CSV here.
        #[arg(long)]
        csv: Option<PathBuf>,
        /// Print the JSON report to stdout instead of the text summary.
        #[arg(long)]
        stdout_json: bool,
        /// Skip the slow brute-force probes (PID space and port binding).
        #[arg(long)]
        quick: bool,
        #[arg(long)]
        no_port_probe: bool,
        #[arg(long)]
        no_brute_force: bool,
        #[arg(long)]
        no_persistence: bool,
        #[arg(long)]
        no_modules: bool,
        /// Compare against a previously saved baseline and report drift.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Save this scan as the known-good baseline.
        #[arg(long)]
        save_baseline: Option<PathBuf>,
        /// Suppression file (finding ids / path patterns).
        #[arg(long)]
        suppressions: Option<PathBuf>,
        /// Minimum severity printed in the text summary.
        #[arg(long, default_value = "low")]
        min_severity: String,
        /// Exit with code 1 if any unsuppressed finding is at/above this severity.
        #[arg(long, default_value = "high")]
        fail_on: String,
        /// No progress output on stderr.
        #[arg(long, short)]
        quiet: bool,
        /// Also save the report as `<scan_id>.json` in this directory (the
        /// desktop app's history folder; used by scheduled scans).
        #[arg(long)]
        history_dir: Option<PathBuf>,
        /// Write AWS Security Hub (ASFF) findings. Files are split into
        /// batches of 100: PATH, PATH-2, ... ready for
        /// `aws securityhub batch-import-findings --findings file://PATH`.
        #[arg(long, requires_all = ["aws_account", "aws_region"])]
        asff: Option<PathBuf>,
        /// 12-digit AWS account id for ASFF export.
        #[arg(long)]
        aws_account: Option<String>,
        /// AWS region for ASFF export, e.g. us-east-1.
        #[arg(long)]
        aws_region: Option<String>,
        /// EC2 instance id when scanning an EC2 host.
        #[arg(long)]
        aws_instance: Option<String>,
        /// Minimum severity exported to ASFF.
        #[arg(long, default_value = "low")]
        asff_min_severity: String,
    },
    /// Re-render a saved JSON report as HTML, CSV or text.
    Render {
        input: PathBuf,
        #[arg(long)]
        html: Option<PathBuf>,
        #[arg(long)]
        csv: Option<PathBuf>,
        #[arg(long, default_value = "low")]
        min_severity: String,
    },
    /// Terminate a process (guarded against PID reuse with --start-time).
    Kill {
        pid: u32,
        #[arg(long, default_value_t = 0)]
        start_time: u64,
    },
    /// Suspend a process for forensic acquisition.
    Suspend {
        pid: u32,
        #[arg(long, default_value_t = 0)]
        start_time: u64,
    },
    /// Resume a suspended process.
    Resume {
        pid: u32,
        #[arg(long, default_value_t = 0)]
        start_time: u64,
    },
}

fn sev(s: &str) -> Result<Severity, String> {
    Severity::parse(s).ok_or_else(|| format!("invalid severity `{s}` (info|low|medium|high|critical)"))
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("panoptic: error: {e}");
            ExitCode::from(2)
        }
    }
}

fn write(path: &std::path::Path, data: &str) -> Result<(), String> {
    panoptic_core::config::write_atomic(path, data.as_bytes()).map_err(|e| format!("writing {}: {e}", path.display()))
}

fn run(cli: Cli) -> Result<u8, String> {
    match cli.cmd {
        Cmd::Scan {
            json,
            html,
            csv,
            stdout_json,
            quick,
            no_port_probe,
            no_brute_force,
            no_persistence,
            no_modules,
            baseline,
            save_baseline,
            suppressions,
            min_severity,
            fail_on,
            quiet,
            history_dir,
            asff,
            aws_account,
            aws_region,
            aws_instance,
            asff_min_severity,
        } => {
            let min = sev(&min_severity)?;
            let fail = sev(&fail_on)?;
            let asff_min = sev(&asff_min_severity)?;
            // Validate the AWS target before spending time on a scan.
            let aws = match (&asff, aws_account, aws_region) {
                (Some(_), Some(account_id), Some(region)) => {
                    let t = AsffTarget { account_id, region, instance_id: aws_instance };
                    t.validate()?;
                    Some(t)
                }
                _ => None,
            };
            let mut opts = if quick { ScanOptions::quick() } else { ScanOptions::default() };
            opts.port_probe &= !no_port_probe;
            opts.brute_force_pids &= !no_brute_force;
            opts.persistence &= !no_persistence;
            opts.kernel_modules &= !no_modules;
            let sup = match &suppressions {
                Some(p) => Suppressions::load(p).map_err(|e| format!("loading suppressions {}: {e}", p.display()))?,
                None => Suppressions::default(),
            };
            let base = match &baseline {
                Some(p) => Some(Baseline::load(p).map_err(|e| format!("loading baseline {}: {e}", p.display()))?),
                None => None,
            };
            let scanner = Scanner::new();
            if !scanner.engine().is_elevated() && !quiet {
                eprintln!("panoptic: warning: not running as root/Administrator — coverage is reduced");
            }
            let tty = std::io::stderr().is_terminal();
            let cancel = CancelToken::new();
            let report = scanner.run(&opts, &sup, base.as_ref(), &cancel, &|p| {
                if !quiet {
                    if tty {
                        eprint!("\r\x1b[2K[{:>3}%] {}", p.percent, p.message);
                    } else {
                        eprintln!("[{:>3}%] {}", p.percent, p.message);
                    }
                }
            });
            if !quiet && tty {
                eprintln!();
            }
            if let Some(p) = &json {
                write(p, &report::to_json(&report))?;
            }
            if let Some(p) = &html {
                write(p, &report::to_html(&report))?;
            }
            if let Some(p) = &csv {
                write(p, &report::to_csv(&report))?;
            }
            if let Some(dir) = &history_dir {
                write(&dir.join(format!("{}.json", report.scan_id)), &report::to_json(&report))?;
            }
            if let (Some(path), Some(target)) = (&asff, &aws) {
                let findings = asff::to_asff(&report, target, asff_min)?;
                let mut batches = asff::chunks(&findings);
                if batches.is_empty() {
                    batches.push(Vec::new()); // always produce the file so automation can rely on it
                }
                for (i, batch) in batches.iter().enumerate() {
                    let p = if i == 0 { path.clone() } else { numbered(path, i + 1) };
                    write(&p, &serde_json::to_string_pretty(batch).map_err(|e| e.to_string())?)?;
                }
                if !quiet {
                    eprintln!("panoptic: wrote {} ASFF finding(s) for account {} in {}", findings.len(), target.account_id, target.region);
                }
            }
            if let Some(p) = &save_baseline {
                Baseline::from_report(&report).save(p).map_err(|e| format!("saving baseline: {e}"))?;
            }
            if stdout_json {
                println!("{}", report::to_json(&report));
            } else {
                print!("{}", report::to_text(&report, min));
            }
            if report.cancelled {
                return Ok(3);
            }
            let failing = report.findings.iter().any(|f| !f.suppressed && f.severity >= fail);
            Ok(u8::from(failing))
        }
        Cmd::Render { input, html, csv, min_severity } => {
            let s = std::fs::read_to_string(&input).map_err(|e| format!("reading {}: {e}", input.display()))?;
            let r = report::from_json(&s).map_err(|e| format!("parsing report: {e}"))?;
            if let Some(p) = &html {
                write(p, &report::to_html(&r))?;
            }
            if let Some(p) = &csv {
                write(p, &report::to_csv(&r))?;
            }
            if html.is_none() && csv.is_none() {
                print!("{}", report::to_text(&r, sev(&min_severity)?));
            }
            Ok(0)
        }
        Cmd::Kill { pid, start_time } => act(pid, start_time, ProcessAction::Terminate),
        Cmd::Suspend { pid, start_time } => act(pid, start_time, ProcessAction::Suspend),
        Cmd::Resume { pid, start_time } => act(pid, start_time, ProcessAction::Resume),
    }
}

/// `out.json` → `out-2.json`.
fn numbered(path: &std::path::Path, n: usize) -> PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "asff".into());
    let name = match path.extension() {
        Some(ext) => format!("{stem}-{n}.{}", ext.to_string_lossy()),
        None => format!("{stem}-{n}"),
    };
    path.with_file_name(name)
}

fn act(pid: u32, start_time: u64, action: ProcessAction) -> Result<u8, String> {
    panoptic_core::platform_engine().act_on_process(pid, start_time, action).map_err(|e| e.to_string())?;
    println!("{action:?} PID {pid}: ok");
    Ok(0)
}
