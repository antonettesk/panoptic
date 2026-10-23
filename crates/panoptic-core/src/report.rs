//! Report exporters: JSON (machine), self-contained HTML (analyst), text (CLI)
//! and CSV (findings, for spreadsheets/SIEM import).

use crate::model::{ScanReport, Severity};
use std::fmt::Write as _;

pub fn to_json(r: &ScanReport) -> String {
    serde_json::to_string_pretty(r).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

pub fn from_json(s: &str) -> Result<ScanReport, serde_json::Error> {
    serde_json::from_str(s)
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '&' => o.push_str("&amp;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

fn csv(s: &str) -> String {
    // Neutralise spreadsheet formula injection, then quote.
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s.to_string() };
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub fn format_epoch(secs: u64) -> String {
    // Civil-from-days (Howard Hinnant), UTC.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, (rem % 3600) / 60, rem % 60)
}

pub fn to_csv(r: &ScanReport) -> String {
    let mut o = String::from("id,severity,category,title,pid,path,mitre,suppressed,evidence\n");
    for f in &r.findings {
        let _ = writeln!(
            o,
            "{},{},{},{},{},{},{},{},{}",
            csv(&f.id),
            f.severity,
            f.category,
            csv(&f.title),
            f.pid.map(|p| p.to_string()).unwrap_or_default(),
            csv(f.path.as_deref().unwrap_or("")),
            f.mitre.as_deref().unwrap_or(""),
            f.suppressed,
            csv(&f.evidence.join(" | "))
        );
    }
    o
}

pub fn to_text(r: &ScanReport, min: Severity) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "PANOPTIC // CROSS-LAYER TRUTH REPORT  v{}", r.tool_version);
    let _ = writeln!(o, "host      : {} ({} {}, kernel {})", r.host.hostname, r.host.os, r.host.arch, r.host.kernel_version);
    let _ = writeln!(o, "scan      : {}  at {}  in {} ms  engine={}  elevated={}", r.scan_id, format_epoch(r.started_at), r.duration_ms, r.engine, r.elevated);
    let s = &r.summary;
    let _ = writeln!(
        o,
        "risk      : {}/100  [critical {}  high {}  medium {}  low {}  suppressed {}]",
        r.risk_score, s.critical, s.high, s.medium, s.low, s.suppressed
    );
    let _ = writeln!(
        o,
        "inventory : {} processes ({} hidden), {} sockets ({} listening, {} hidden), {} autostart entries, {} modules ({} hidden)",
        s.processes, s.hidden_processes, s.sockets, s.listening, s.hidden_sockets, s.persistence_entries, s.modules, s.hidden_modules
    );
    for st in r.stages.iter().filter(|s| !s.ok || s.message.is_some()) {
        let _ = writeln!(o, "stage     : {} {} {}", st.stage, if st.ok { "ok" } else { "FAILED" }, st.message.clone().unwrap_or_default());
    }
    if r.cancelled {
        let _ = writeln!(o, "WARNING   : scan was cancelled; results are partial");
    }
    let shown: Vec<_> = r.findings.iter().filter(|f| !f.suppressed && f.severity >= min).collect();
    let _ = writeln!(o, "\n{} finding(s) at or above {}:", shown.len(), min);
    for f in shown {
        let _ = writeln!(o, "\n[{}] {}", f.severity, f.title);
        let _ = writeln!(o, "    id: {}  category: {}  mitre: {}", f.id, f.category, f.mitre.as_deref().unwrap_or("-"));
        if let Some(p) = &f.path {
            let _ = writeln!(o, "    path: {p}");
        }
        for e in &f.evidence {
            let _ = writeln!(o, "    - {e}");
        }
        if !f.recommendation.is_empty() {
            let _ = writeln!(o, "    > {}", f.recommendation);
        }
    }
    o
}

/// The Panoptic mark (panopticon plan: 12 cells around a watchtower) as an
/// inline SVG. The first `lit` cells clockwise from the top take `color`, so
/// the report header doubles as the risk gauge, exactly like the app.
/// Geometry mirrors ui/src/brand/mark.ts.
pub fn mark_svg(size: u32, lit: usize, color: &str) -> String {
    const CELLS: usize = 12;
    let (cx, cy, outer, inner, gap) = (32.0_f64, 32.0_f64, 30.0_f64, 22.5_f64, 5.0_f64);
    let p = |r: f64, deg: f64| {
        let a = deg.to_radians();
        (((cx + r * a.sin()) * 100.0).round() / 100.0, ((cy - r * a.cos()) * 100.0).round() / 100.0)
    };
    let mut cells = String::new();
    for i in 0..CELLS {
        let step = 360.0 / CELLS as f64;
        let (a0, a1) = (i as f64 * step - step / 2.0 + gap / 2.0, i as f64 * step + step / 2.0 - gap / 2.0);
        let ((x0, y0), (x1, y1), (x2, y2), (x3, y3)) = (p(outer, a0), p(outer, a1), p(inner, a1), p(inner, a0));
        let fill = if i < lit { color } else { "#2B3346" };
        let _ = write!(cells, r#"<path d="M{x0} {y0}A{outer} {outer} 0 0 1 {x1} {y1}L{x2} {y2}A{inner} {inner} 0 0 0 {x3} {y3}Z" fill="{fill}"/>"#);
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 64 64" aria-hidden="true">{cells}<circle cx="32" cy="32" r="18.5" fill="#0F1219" stroke="#232835" stroke-width="0.6"/></svg>"##
    )
}

/// Cells lit for a 0–100 score (same rule as the app's cell gauge).
pub fn lit_cells(score: u8) -> usize {
    if score == 0 {
        0
    } else {
        ((f64::from(score.min(100)) / 100.0 * 12.0).round() as usize).max(1)
    }
}

fn risk_color(score: u8) -> &'static str {
    match score {
        70.. => "#FF4D5E",
        40..=69 => "#FF9F43",
        1..=39 => "#FACC15",
        0 => "#2DE2C5",
    }
}

fn risk_label(score: u8) -> &'static str {
    match score {
        70.. => "Compromised",
        40..=69 => "High risk",
        1..=39 => "Needs review",
        0 => "Clean",
    }
}

pub fn to_html(r: &ScanReport) -> String {
    let sev_color = |s: Severity| match s {
        Severity::Critical => "#FF4D5E",
        Severity::High => "#FF9F43",
        Severity::Medium => "#FACC15",
        Severity::Low => "#60A5FA",
        Severity::Info => "#626A7E",
    };
    let mut findings = String::new();
    for f in &r.findings {
        let mut ev = String::new();
        for e in &f.evidence {
            let _ = write!(ev, "<li><code>{}</code></li>", esc(e));
        }
        let _ = write!(
            findings,
            r#"<article class="f{sup}" style="--c:{c}"><header><span class="sev" style="background:{c}">{sev}</span><h3>{t}</h3></header>
<p>{d}</p><dl><dt>Category</dt><dd>{cat}</dd><dt>MITRE</dt><dd>{m}</dd>{pid}{path}<dt>ID</dt><dd><code>{id}</code></dd></dl>
<ul>{ev}</ul>{rec}</article>"#,
            sup = if f.suppressed { " suppressed" } else { "" },
            c = sev_color(f.severity),
            sev = f.severity,
            t = esc(&f.title),
            d = esc(&f.description),
            cat = f.category,
            m = esc(f.mitre.as_deref().unwrap_or("-")),
            pid = f.pid.map(|p| format!("<dt>PID</dt><dd>{p}</dd>")).unwrap_or_default(),
            path = f.path.as_deref().map(|p| format!("<dt>Path</dt><dd><code>{}</code></dd>", esc(p))).unwrap_or_default(),
            id = esc(&f.id),
            ev = ev,
            rec = if f.recommendation.is_empty() { String::new() } else { format!("<p class=\"rec\">↳ {}</p>", esc(&f.recommendation)) }
        );
    }
    let mut procs = String::new();
    for p in &r.processes {
        let _ = write!(
            procs,
            "<tr class=\"{}\"><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            if p.is_discrepant {
                "ghost"
            } else if !p.flags.is_empty() {
                "flag"
            } else {
                ""
            },
            p.pid,
            p.ppid.map(|x| x.to_string()).unwrap_or_default(),
            esc(&p.name),
            esc(&p.path),
            esc(p.user.as_deref().unwrap_or("")),
            if p.is_discrepant { "GHOST" } else { "verified" }
        );
    }
    let mut socks = String::new();
    for s in &r.sockets {
        let _ = write!(
            socks,
            "<tr class=\"{}\"><td>{}</td><td>{}:{}</td><td>{}:{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            if s.hidden {
                "ghost"
            } else if s.suspicious {
                "flag"
            } else {
                ""
            },
            s.protocol,
            esc(&s.local_address),
            s.local_port,
            esc(&s.remote_address),
            s.remote_port,
            esc(&s.state),
            s.pid.map(|x| x.to_string()).unwrap_or_else(|| "?".into()),
            esc(s.process_name.as_deref().unwrap_or(""))
        );
    }
    let mut persist = String::new();
    for p in &r.persistence {
        let _ = write!(
            persist,
            "<tr class=\"{}\"><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
            if p.risk_level >= Severity::Medium { "flag" } else { "" },
            p.risk_level,
            esc(&p.mechanism),
            esc(&p.location),
            esc(&p.command),
            esc(&p.reasons.join("; "))
        );
    }
    let s = &r.summary;
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Panoptic Report — {host}</title>
<style>
:root{{color-scheme:dark;--ink:#090B10;--panel:#0F1219;--raised:#161A23;--line:#232835;--fg:#E9ECF2;--mute:#949CB0;--beacon:#C8F135;--teal:#2DE2C5}}
*{{box-sizing:border-box}}body{{margin:0 auto;background:var(--ink);color:var(--fg);font:14px/1.55 'Inter Variable',Inter,'Segoe UI',system-ui,sans-serif;padding:32px;max-width:1360px}}
h1,h2,h3,.brand,.card b{{font-family:'Space Grotesk Variable','Space Grotesk','Segoe UI',system-ui,sans-serif}}
code,td code{{font-family:'JetBrains Mono',ui-monospace,Consolas,monospace;font-size:12px;color:#D7DCE6;word-break:break-all}}
.hero{{display:flex;gap:28px;align-items:center;padding:28px;border:1px solid var(--line);border-radius:20px;background:radial-gradient(600px 240px at 85% 0%,rgba(200,241,53,.12),transparent),var(--panel)}}
.gauge{{position:relative;flex:none}}.gauge span{{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;font:600 34px 'Space Grotesk',system-ui}}.gauge small{{font-size:10px;letter-spacing:.2em;color:var(--mute)}}
.brand{{font-weight:700;letter-spacing:.22em;font-size:13px;color:var(--beacon)}}
h1{{margin:6px 0 4px;font-size:28px;letter-spacing:-.01em}}h2{{margin:40px 0 12px;font-size:18px;display:flex;gap:10px;align-items:center}}h2::before{{content:"";width:4px;height:18px;border-radius:2px;background:var(--beacon)}}
.meta{{color:var(--mute);font-size:13px}}.level{{display:inline-block;margin-top:10px;padding:3px 12px;border-radius:999px;font:600 11px 'Space Grotesk',system-ui;letter-spacing:.14em;text-transform:uppercase}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px;color:var(--mute);font-size:12px}}.card b{{display:block;font-size:28px;color:var(--fg);font-weight:600}}
article{{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c,var(--line));border-radius:14px;padding:16px 18px;margin:10px 0}}article.suppressed{{opacity:.45}}
article header{{display:flex;gap:10px;align-items:center}}article h3{{margin:0;font-size:15px;font-weight:600}}.sev{{color:#090B10;font:700 10.5px 'Space Grotesk',system-ui;letter-spacing:.08em;padding:3px 8px;border-radius:6px}}
article p{{color:#C9CEDA}}dl{{display:grid;grid-template-columns:110px 1fr;gap:3px 10px;color:var(--mute);font-size:13px}}dd{{margin:0;color:var(--fg);word-break:break-all}}
ul{{background:var(--ink);border:1px solid var(--line);border-radius:10px;padding:10px 14px 10px 28px}}.rec{{color:var(--teal)}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}}
th{{background:var(--raised);color:var(--mute);font:600 11px 'Space Grotesk',system-ui;letter-spacing:.08em;text-transform:uppercase}}
td,th{{border-bottom:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}}
tr.ghost{{background:rgba(255,77,94,.12)}}tr.flag{{background:rgba(255,159,67,.07)}}
footer{{margin-top:40px;display:flex;gap:10px;align-items:center;color:var(--mute);font-size:12px}}
@media print{{body{{background:#fff;color:#000}}.hero,.card,article,table{{background:#fff}}}}
</style></head><body>
<section class="hero">
<div class="gauge">{gauge}<span>{risk}<small>/ 100</small></span></div>
<div><div class="brand">PANOPTIC</div><h1>Cross-layer truth report</h1>
<p class="meta">{host} · {os} · kernel {kernel}<br>scan {id} · {when} · {dur} ms · engine {engine} · elevated {elev}</p>
<span class="level" style="color:{riskc};background:{riskc}22">{level}</span></div>
</section>
<div class="grid">
<div class="card">Critical<b style="color:#FF4D5E">{c}</b></div><div class="card">High<b style="color:#FF9F43">{h}</b></div><div class="card">Medium<b style="color:#FACC15">{m}</b></div>
<div class="card">Hidden processes<b>{hp}</b></div><div class="card">Hidden sockets<b>{hs}</b></div><div class="card">Hidden modules<b>{hm}</b></div>
</div>
<h2>Findings ({nf})</h2>{findings}
<h2>Processes ({np})</h2><table><tr><th>PID</th><th>PPID</th><th>Name</th><th>Path</th><th>User</th><th>Status</th></tr>{procs}</table>
<h2>Sockets ({ns})</h2><table><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th><th>PID</th><th>Process</th></tr>{socks}</table>
<h2>Persistence ({npe})</h2><table><tr><th>Risk</th><th>Mechanism</th><th>Location</th><th>Command</th><th>Reasons</th></tr>{persist}</table>
<footer>{mark} Generated offline by Panoptic {ver} · See every layer.</footer>
</body></html>"#,
        host = esc(&r.host.hostname),
        os = esc(&r.host.os),
        kernel = esc(&r.host.kernel_version),
        id = esc(&r.scan_id),
        when = format_epoch(r.started_at),
        dur = r.duration_ms,
        engine = esc(&r.engine),
        elev = r.elevated,
        riskc = risk_color(r.risk_score),
        level = risk_label(r.risk_score),
        gauge = mark_svg(132, lit_cells(r.risk_score), risk_color(r.risk_score)),
        mark = mark_svg(18, 1, "#C8F135"),
        risk = r.risk_score,
        c = s.critical,
        h = s.high,
        m = s.medium,
        hp = s.hidden_processes,
        hs = s.hidden_sockets,
        hm = s.hidden_modules,
        nf = r.findings.len(),
        findings = findings,
        np = r.processes.len(),
        procs = procs,
        ns = r.sockets.len(),
        socks = socks,
        npe = r.persistence.len(),
        persist = persist,
        ver = esc(&r.tool_version),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, FindingCategory};

    #[test]
    fn epoch_format() {
        assert_eq!(format_epoch(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_epoch(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn html_escapes_untrusted_strings() {
        let mut r = ScanReport::default();
        r.findings.push(
            Finding::new(FindingCategory::Persistence, Severity::High, "x", "<script>alert(1)</script>", "d").evidence("\"><img src=x onerror=alert(1)>"),
        );
        let h = to_html(&r);
        assert!(!h.contains("<script>alert"));
        assert!(!h.contains("<img src=x"));
    }

    #[test]
    fn report_gauge_matches_app_rule() {
        assert_eq!(lit_cells(0), 0);
        assert_eq!(lit_cells(1), 1);
        assert_eq!(lit_cells(50), 6);
        assert_eq!(lit_cells(100), 12);
        let svg = mark_svg(64, 3, "#FF4D5E");
        assert_eq!(svg.matches("<path").count(), 12);
        assert_eq!(svg.matches("#FF4D5E").count(), 3);
    }

    #[test]
    fn csv_neutralises_formulas() {
        let mut r = ScanReport::default();
        r.findings.push(Finding::new(FindingCategory::Persistence, Severity::High, "x", "=cmd|' /C calc'!A0", "d"));
        let c = to_csv(&r);
        assert!(c.contains("\"'=cmd"));
    }

    #[test]
    fn json_roundtrip() {
        let mut r = ScanReport::default();
        r.findings.push(Finding::new(FindingCategory::HiddenProcess, Severity::Critical, "x", "t", "d"));
        let back = from_json(&to_json(&r)).unwrap();
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.findings[0].severity, Severity::Critical);
    }
}
