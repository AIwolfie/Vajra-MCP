# Release Checklist - Vajra MCP

Use this checklist to verify production readiness before pushing a release.

---

## 1. Pre-Release QA
- [ ] Run `python -m cybermcp doctor` locally and verify all configurations print correctly.
- [ ] Run the complete test suite: `python -m unittest discover tests` and verify 31/31 tests pass.
- [ ] Verify that `pyproject.toml` version matches target release (e.g. `1.0.0`).
- [ ] Verify `CHANGELOG.md` is updated with changes.

## 2. Release Build
- [ ] Clean build artifacts: `rm -rf dist/ build/ *.egg-info`
- [ ] Run python build wrapper: `python -m build`
- [ ] Inspect generated wheel and sdist files in `dist/` (verify sizes and metadata).

## 3. Deployment
- [ ] Tag the git commit: `git tag -a v1.0.0 -m "Release v1.0.0"`
- [ ] Push tag to origin: `git push origin v1.0.0`
- [ ] Upload distribution packages to PyPI: `twine upload dist/*`
