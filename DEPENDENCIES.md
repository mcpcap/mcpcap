# Locked dependencies and security updates

CI, release packaging, and Docker install dependencies from `uv.lock` with
uv 0.12.19. A stale lock causes `--locked` to fail instead of silently resolving
new package versions. Python 3.10, 3.11, and 3.12 are tested in CI.

The `build` dependency group locks setuptools and setuptools-scm. Install the
build group before installing the project without build isolation, so its build
backend also comes from the reviewed lock:

```bash
uv sync --locked --extra dev --extra test --group build --no-install-project
uv sync --locked --extra dev --extra test --group build --no-build-isolation
uv run --locked --no-sync pytest tests/
uv run --locked --no-sync ruff check .
uv run --locked --no-sync ruff format --check .
uv run --locked --no-sync python -m build --no-isolation
uv run --locked --no-sync twine check dist/*
```

Docker uses the same two-stage dependency installation with only production
packages and the build group. It installs a non-editable project, retains the
non-root runtime user, and obtains its version from `MCPPCAP_VERSION` through
setuptools-scm. Development and documentation extras are excluded. Builds behind
an HTTPS proxy may pass a combined trusted CA bundle as the optional BuildKit
secret `proxy_ca`; the bundle is never copied into the image.

## Audit snapshot

On 2026-09-30, targeted upgrades of anyio, click, cryptography, idna, mcp,
pydantic-settings, pygments, pyjwt, python-multipart, setuptools, and starlette
removed the advisories in the baseline lock. FastMCP's existing constraint
`>=2.12.2,<3.3.0` and locked version 3.2.0 were preserved.

All extras and dependency groups were exported and audited with pip-audit 2.10.1
on Linux for Python 3.10, 3.11, and 3.12. Each audit reported zero known
vulnerabilities and no skipped dependencies (125 packages for Python 3.10/3.11,
124 for Python 3.12). These counts reflect environment markers and the advisory
database at audit time, and should be refreshed when updating the lock.

```bash
uv export --locked --all-extras --all-groups --no-emit-project --no-hashes \
  --format requirements-txt --output-file /tmp/mcpcap-requirements.txt
# Repeat with --python 3.11 and --python 3.12 to cover their markers.
uvx --python 3.10 pip-audit==2.10.1 --disable-pip --no-deps \
  --requirement /tmp/mcpcap-requirements.txt
```

The export pins every requirement; the lock retains artifact hashes for
installation. This audit checks dependency advisories and does not substitute
for GitHub Dependabot alert access or an application security review.
