# AWS integration

Panoptic produces findings in the [AWS Security Finding Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html), so they appear in AWS Security Hub next to GuardDuty, Inspector and partner findings.

**Panoptic itself never calls AWS APIs and never stores credentials.** You import findings with your own tooling and IAM permissions. This keeps the scanner offline and keeps credentials out of a tool that runs with root/Administrator privileges.

## Field mapping

| ASFF field | Value |
|---|---|
| `Id` | `panoptic/<hostname>/<finding id>`. Stable, so re-imports update the existing finding |
| `ProductArn` | `arn:<partition>:securityhub:<region>:<account>:product/<account>/default` |
| `GeneratorId` | `panoptic/<category>` |
| `Types` | e.g. `TTPs/Defense Evasion/Rootkit`, `TTPs/Persistence/Autostart Execution` |
| `Severity.Label` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFORMATIONAL` |
| `Resources` | `AwsEc2Instance` when `--aws-instance` is given; otherwise `Other` with the hostname |
| `Remediation.Recommendation` | Panoptic's recommendation, plus a link to the ATT&CK technique |
| `ProductFields` | category, scan ID, engine, elevation, PID, path, up to 8 evidence lines |

Partitions (`aws`, `aws-cn`, `aws-us-gov`) are derived from the region. Suppressed findings are never exported.

## Single host

```bash
panoptic-cli scan --asff asff.json --aws-account 123456789012 --aws-region eu-west-1 --aws-instance i-0abc1234def567890
```

```bash
aws securityhub batch-import-findings --findings file://asff.json
```

Each file holds at most 100 findings, the `BatchImportFindings` limit. Larger results are written to `asff.json`, `asff-2.json`, and so on.

Minimal IAM policy for the importing principal:

```json
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow", "Action": "securityhub:BatchImportFindings", "Resource": "*" }]
}
```

## EC2 fleets with Systems Manager

1. Install the Panoptic `.deb`, or copy `panoptic-cli`, onto your instances (for example with SSM Distributor or your AMI pipeline).
2. Run the scan with **SSM Run Command** (`AWS-RunShellScript`):

   ```bash
   set -euo pipefail
   TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
   IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
   ACCT=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .accountId)
   REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
   panoptic-cli scan --quiet --asff /tmp/panoptic-asff.json \
     --aws-account "$ACCT" --aws-region "$REGION" --aws-instance "$IID" || true
   for f in /tmp/panoptic-asff*.json; do
     aws securityhub batch-import-findings --region "$REGION" --findings "file://$f"
   done
   ```

   The instance-metadata calls happen in *your* script, not in Panoptic.

3. Schedule it with an **SSM State Manager association**, or with **EventBridge Scheduler** targeting Run Command.
4. In Security Hub, build automation rules or EventBridge rules on `ProductName = Panoptic` and `Severity.Label = CRITICAL` to page your on-call team.

## Using the desktop app

- Enable **Settings → Integrations → AWS Security Hub**. Enter the account ID, region and, optionally, the EC2 instance ID.
- Choose **Export → AWS Security Hub (ASFF)** to write the batch files.
- Import them with the AWS CLI command shown in the app.
