# Aegis Release Checklist

Use this checklist before tagging or publishing Aegis packages.

## Pre-release verification

- [ ] `npm ci`
- [ ] `npm run verify`
- [ ] `npm run test:mutation`
- [ ] CLI examples from README still work
- [ ] Example policies and actions validate
- [ ] Threat model reviewed for changed assumptions
- [ ] Security limitations still accurate

## Security-sensitive review

Require explicit review when a release changes:

- Canonical serialization
- SHA-256 digest inputs
- Ed25519 signing/verification
- Policy precedence
- Approval grant verification
- Audit chain verification
- Redaction patterns
- CLI JSON output shape

## Versioning notes

Until `1.0.0`, breaking changes may occur, but every breaking change should still be documented in the release notes.

Recommended release-note sections:

- Added
- Changed
- Fixed
- Security
- Migration notes
- Verification evidence

## Release artifact expectations

For published packages or binaries:

- [ ] Tag uses `vX.Y.Z` format
- [ ] Changelog entry exists
- [ ] Build output is reproducible from source
- [ ] Package contents reviewed for secrets and generated clutter
- [ ] Release notes include verification commands and results

## Post-release checks

- [ ] GitHub release page created
- [ ] CI is green on the release tag
- [ ] Dependency alerts reviewed
- [ ] Next roadmap milestone updated
