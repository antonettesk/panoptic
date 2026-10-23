## Summary

<!-- What does this change and why? Link related issues (Fixes #123). -->

## Type of change

- [ ] Detection (new rule or tuning)
- [ ] Bug fix
- [ ] Feature / UX
- [ ] Translation
- [ ] Docs / build / CI

## Testing

- [ ] `npm test` passes (Rust + UI)
- [ ] `npm run lint` passes (clippy `-D warnings` + TypeScript)
- [ ] For detections: unit test added, **and** ran a real scan on a clean machine to check for false positives (OS + result below)
- [ ] New UI strings added to **all** locale files

<!-- False-positive testing notes: OS, privileges, findings before/after -->

## Checklist

- [ ] Scanning remains read-only and offline
- [ ] Findings include evidence, an ATT&CK technique and a recommendation
- [ ] CHANGELOG.md updated (user-facing changes)
