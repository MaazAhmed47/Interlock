# Releasing Interlock

One page. Follow in order. A release is a PR like any other change — nothing
here is done directly on `main`.

## 1. Pick the version

Semantic Versioning, pre-releases as `X.Y.Z-alpha.N` / `X.Y.Z-beta.N`.
While the product is pre-1.0, breaking changes bump the minor version.

## 2. Update version metadata (all must match)

| File | Field |
| --- | --- |
| `pyproject.toml` | `version` |
| `interlock-web/package.json` | `version` |
| `helm/Chart.yaml` | `version` and `appVersion` |
| `proxy.py` | `FastAPI(version=...)` (shown in `/docs`) |
| `core/siem.py` | `service.version` in the Elastic/ECS event |

## 3. Update `CHANGELOG.md`

Keep a Changelog format. Move entries from `[Unreleased]` into a new
`[X.Y.Z] - YYYY-MM-DD` section, add the compare link at the bottom. Entries
must be factual — no marketing language, no claims a buyer can't reproduce.

## 4. Verify locally

```bash
python -m pytest tests/ -q        # entire directory, no file list
ruff check core/ routes/ proxy.py
black --check --target-version py312 core/ routes/ proxy.py
mypy core/ routes/ --ignore-missing-imports
cd interlock-web && npm run build
```

## 5. PR, merge, confirm CI

Open a PR with the version + changelog changes. All CI jobs (backend tests,
dependency audit, secret scan, dashboard build, Helm, Docker) must be green.
Merging to `main` auto-deploys the backend (Render) and frontend (Vercel), so
the merge is the deploy.

## 6. Tag

Tag the merge commit on `main`, matching the changelog version, `v`-prefixed:

```bash
git tag -a v0.2.0-alpha.1 -m "0.2.0-alpha.1"
git push origin v0.2.0-alpha.1
```

## 7. Build and label the image

```bash
docker build -t interlock:v0.2.0-alpha.1 .
```

Push to a registry only if the release is meant for external consumption;
the offline demo and Helm chart reference the image by tag.

## 8. GitHub release (optional for alphas)

Create a release from the tag; paste the changelog section as the body. Mark
pre-releases as such.
