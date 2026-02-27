# Release Checklist

Steps to publish a new version of `@elvatis_com/clawhub-scanner`.

## Pre-release

- [ ] All CI checks pass on `main` (lint, test, build)
- [ ] No `TODO` or `FIXME` items blocking release
- [ ] Detection rules tested against known-malicious samples
- [ ] Allowlist suppression working correctly
- [ ] README.md is up to date with any new features or CLI flags

## Version Bump

- [ ] Update `version` in `package.json` (semver)
- [ ] Commit: `chore: bump version to X.Y.Z`
- [ ] Create git tag: `git tag vX.Y.Z`

## Build and Verify

- [ ] Run `npm run ci` (lint + test + build) locally
- [ ] Verify `dist/` output looks correct
- [ ] Test CLI manually: `node dist/index.js scan --help`
- [ ] Test a scan against a sample skill directory

## Publish

- [ ] Ensure you are logged in: `npm whoami`
- [ ] Publish: `npm publish --access public`
- [ ] Verify on npm: https://www.npmjs.com/package/@elvatis_com/clawhub-scanner

## Post-release

- [ ] Push tag: `git push origin vX.Y.Z`
- [ ] Create GitHub release with changelog notes
- [ ] Announce in relevant channels
