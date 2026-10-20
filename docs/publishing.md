# Publishing ProofMesh

## Install from source (today)

```bash
git clone https://github.com/sayan9168/sayanox-proofmesh
cd sayanox-proofmesh
pip install -e .
proofmesh version
```

## PyPI (when ready)

Package name on PyPI: **sayanox-proofmesh**  
Import / CLI: `proofmesh`

### One-time setup

1. Create account on https://pypi.org and https://test.pypi.org  
2. Create API token (Account → API tokens)  
3. Store as GitHub secret `PYPI_API_TOKEN` (repo → Settings → Secrets)

### Build locally

```bash
pip install build twine
python -m build
twine check dist/*
# Test upload
twine upload --repository testpypi dist/*
# Production
twine upload dist/*
```

### Tag-triggered release (optional)

After `v0.2.0` (or later) is tagged and CI is green:

```bash
git tag -a v0.2.0 -m "ProofMesh 0.2.0"
git push origin v0.2.0
```

Then either upload with `twine` or enable `.github/workflows/publish.yml` once `PYPI_API_TOKEN` is set.

### Version bump

Edit `pyproject.toml` → `[project].version` and `src/proofmesh/__init__.py` → `__version__`, then CHANGELOG.
