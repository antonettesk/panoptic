//! AWS Security Finding Format (ASFF) export.
//!
//! Panoptic stays offline: this module only *formats* findings so an analyst
//! can import them with their own credentials, e.g.
//! `aws securityhub batch-import-findings --findings file://panoptic-asff-1.json`.
//! BatchImportFindings accepts at most 100 findings per call, so callers
//! should use [`chunks`].

use crate::model::{Finding, FindingCategory, ScanReport, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MAX_PER_BATCH: usize = 100;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct AsffTarget {
    /// 12-digit AWS account id that owns the findings.
    pub account_id: String,
    /// Region of the Security Hub the findings are imported into, e.g. `eu-west-1`.
    pub region: String,
    /// Optional EC2 instance id when scanning an EC2 host; the resource is
    /// then reported as `AwsEc2Instance` instead of `Other`.
    #[serde(default)]
    pub instance_id: Option<String>,
}

impl AsffTarget {
    pub fn validate(&self) -> Result<(), String> {
        if self.account_id.len() != 12 || !self.account_id.chars().all(|c| c.is_ascii_digit()) {
            return Err("AWS account id must be exactly 12 digits".into());
        }
        let r = &self.region;
        let valid_region = r.len() >= 9 && r.split('-').count() >= 3 && r.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid_region {
            return Err(format!("`{r}` is not a valid AWS region (e.g. us-east-1)"));
        }
        if let Some(i) = &self.instance_id {
            if !i.is_empty() && !(i.starts_with("i-") && i.len() >= 10 && i[2..].chars().all(|c| c.is_ascii_hexdigit())) {
                return Err(format!("`{i}` is not a valid EC2 instance id (e.g. i-0abc1234def567890)"));
            }
        }
        Ok(())
    }

    fn partition(&self) -> &'static str {
        if self.region.starts_with("cn-") {
            "aws-cn"
        } else if self.region.starts_with("us-gov-") {
            "aws-us-gov"
        } else {
            "aws"
        }
    }
}

/// RFC 3339 / ISO 8601 UTC timestamp, as ASFF requires.
pub fn iso8601(secs: u64) -> String {
    let s = crate::report::format_epoch(secs); // "YYYY-MM-DD HH:MM:SS UTC"
    format!("{}T{}Z", &s[..10], &s[11..19])
}

fn label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "INFORMATIONAL",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn types(c: FindingCategory) -> &'static str {
    match c {
        FindingCategory::HiddenProcess | FindingCategory::HiddenSocket | FindingCategory::HiddenModule => "TTPs/Defense Evasion/Rootkit",
        FindingCategory::ProcessAnomaly => "TTPs/Execution/Suspicious Process",
        FindingCategory::SuspiciousSocket => "TTPs/Command and Control/Suspicious Network Activity",
        FindingCategory::Persistence => "TTPs/Persistence/Autostart Execution",
        FindingCategory::LoaderHijack => "TTPs/Persistence/Hijack Execution Flow",
        FindingCategory::KernelIntegrity => "Software and Configuration Checks/Industry and Regulatory Standards/Host Hardening",
        FindingCategory::BaselineDrift => "Unusual Behaviors/Host/Baseline Drift",
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

/// Convert every unsuppressed finding at or above `min` into ASFF.
pub fn to_asff(report: &ScanReport, target: &AsffTarget, min: Severity) -> Result<Vec<Value>, String> {
    target.validate()?;
    let part = target.partition();
    let acct = &target.account_id;
    let region = &target.region;
    let product_arn = format!("arn:{part}:securityhub:{region}:{acct}:product/{acct}/default");
    let ts = iso8601(report.started_at);
    let host = if report.host.hostname.is_empty() { "unknown-host" } else { &report.host.hostname };
    let resource = match target.instance_id.as_deref().filter(|i| !i.is_empty()) {
        Some(i) => json!({ "Type": "AwsEc2Instance", "Id": format!("arn:{part}:ec2:{region}:{acct}:instance/{i}"), "Partition": part, "Region": region }),
        None => json!({ "Type": "Other", "Id": format!("panoptic:host/{host}"), "Partition": part, "Region": region,
                        "Details": { "Other": { "Hostname": host, "OS": truncate(&report.host.os, 128), "Kernel": truncate(&report.host.kernel_version, 128) } } }),
    };
    Ok(report.findings.iter().filter(|f| !f.suppressed && f.severity >= min).map(|f| finding(f, &product_arn, acct, &ts, &resource, host, report)).collect())
}

fn finding(f: &Finding, product_arn: &str, acct: &str, ts: &str, resource: &Value, host: &str, r: &ScanReport) -> Value {
    let mut product_fields = serde_json::Map::new();
    product_fields.insert("Panoptic/Category".into(), json!(f.category.to_string()));
    product_fields.insert("Panoptic/ScanId".into(), json!(r.scan_id));
    product_fields.insert("Panoptic/Engine".into(), json!(r.engine));
    product_fields.insert("Panoptic/Elevated".into(), json!(r.elevated.to_string()));
    if let Some(m) = &f.mitre {
        product_fields.insert("Panoptic/MitreTechnique".into(), json!(m));
    }
    if let Some(p) = f.pid {
        product_fields.insert("Panoptic/Pid".into(), json!(p.to_string()));
    }
    if let Some(p) = &f.path {
        product_fields.insert("Panoptic/Path".into(), json!(truncate(p, 2048)));
    }
    for (i, e) in f.evidence.iter().take(8).enumerate() {
        product_fields.insert(format!("Panoptic/Evidence{}", i + 1), json!(truncate(e, 2048)));
    }
    let mut v = json!({
        "SchemaVersion": "2018-10-08",
        // Stable per host + finding so re-imports update instead of duplicating.
        "Id": format!("panoptic/{host}/{}", f.id),
        "ProductArn": product_arn,
        "ProductName": "Panoptic",
        "CompanyName": "Panoptic",
        "GeneratorId": format!("panoptic/{}", f.category),
        "AwsAccountId": acct,
        "Types": [types(f.category)],
        "CreatedAt": ts,
        "UpdatedAt": ts,
        "Severity": { "Label": label(f.severity) },
        "Title": truncate(&f.title, 256),
        "Description": truncate(&f.description, 1024),
        "ProductFields": product_fields,
        "Resources": [resource],
        "RecordState": "ACTIVE",
        "Workflow": { "Status": "NEW" }
    });
    if !f.recommendation.is_empty() {
        let mut rec = json!({ "Text": truncate(&f.recommendation, 512) });
        if let Some(m) = &f.mitre {
            let (base, sub) = m.split_once('.').unwrap_or((m, ""));
            rec["Url"] = json!(format!("https://attack.mitre.org/techniques/{base}/{sub}"));
        }
        v["Remediation"] = json!({ "Recommendation": rec });
    }
    v
}

/// Split into BatchImportFindings-sized payloads.
pub fn chunks(findings: &[Value]) -> Vec<Vec<Value>> {
    findings.chunks(MAX_PER_BATCH).map(|c| c.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> AsffTarget {
        AsffTarget { account_id: "123456789012".into(), region: "eu-west-1".into(), instance_id: None }
    }

    #[test]
    fn validates_inputs() {
        assert!(target().validate().is_ok());
        assert!(AsffTarget { account_id: "12".into(), ..target() }.validate().is_err());
        assert!(AsffTarget { region: "mars".into(), ..target() }.validate().is_err());
        assert!(AsffTarget { instance_id: Some("abc".into()), ..target() }.validate().is_err());
        assert!(AsffTarget { instance_id: Some("i-0abc1234def567890".into()), ..target() }.validate().is_ok());
    }

    #[test]
    fn iso_timestamps() {
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn converts_and_filters() {
        let mut r = ScanReport { started_at: 1_700_000_000, scan_id: "s1".into(), ..Default::default() };
        r.host.hostname = "web-01".into();
        r.findings.push(Finding::new(FindingCategory::HiddenProcess, Severity::Critical, "a", "Ghost", "d").mitre("T1014").recommend("Isolate"));
        r.findings.push(Finding::new(FindingCategory::Persistence, Severity::Low, "b", "Low one", "d"));
        let mut sup = Finding::new(FindingCategory::Persistence, Severity::High, "c", "Suppressed", "d");
        sup.suppressed = true;
        r.findings.push(sup);
        let out = to_asff(&r, &target(), Severity::Medium).unwrap();
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f["SchemaVersion"], "2018-10-08");
        assert_eq!(f["Severity"]["Label"], "CRITICAL");
        assert_eq!(f["ProductArn"], "arn:aws:securityhub:eu-west-1:123456789012:product/123456789012/default");
        assert_eq!(f["Types"][0], "TTPs/Defense Evasion/Rootkit");
        assert_eq!(f["Resources"][0]["Type"], "Other");
        assert_eq!(f["Remediation"]["Recommendation"]["Url"], "https://attack.mitre.org/techniques/T1014/");
        assert!(f["Id"].as_str().unwrap().starts_with("panoptic/web-01/"));
    }

    #[test]
    fn ec2_resource_and_partitions() {
        let r = ScanReport { findings: vec![Finding::new(FindingCategory::HiddenSocket, Severity::High, "x", "t", "d")], ..Default::default() };
        let t = AsffTarget { region: "cn-north-1".into(), instance_id: Some("i-0abc1234def567890".into()), ..target() };
        let out = to_asff(&r, &t, Severity::Info).unwrap();
        assert_eq!(out[0]["Resources"][0]["Type"], "AwsEc2Instance");
        assert_eq!(out[0]["Resources"][0]["Id"], "arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-0abc1234def567890");
    }

    #[test]
    fn batches_of_100() {
        let v: Vec<Value> = (0..250).map(|i| json!(i)).collect();
        let c = chunks(&v);
        assert_eq!(c.iter().map(Vec::len).collect::<Vec<_>>(), vec![100, 100, 50]);
    }
}
