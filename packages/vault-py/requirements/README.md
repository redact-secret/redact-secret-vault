# Hash-locked requirements for CI and release

These files pin every dependency by hash so the workflows install exactly what was reviewed
(`pip install --require-hashes -r ...`). They are generated, not edited:

```bash
cd packages/vault-py
c() { uv pip compile --universal --generate-hashes --python-version 3.10 --quiet "$@"; }
c pyproject.toml --extra test --extra lint --extra crypto --extra aws-kms -o requirements/ci-test.txt
c pyproject.toml <(printf 'psycopg[binary]\npsycopg-pool\n') --extra test --extra lint --extra crypto --extra postgres -o requirements/ci-postgres.txt
c pyproject.toml --extra test --extra lint --extra crypto -o requirements/release-test.txt
c requirements/build-tools.in -o requirements/build-tools.txt
```

`--universal` resolves for every supported Python (3.10 to 3.13) and platform, using markers.
The package under test is then installed with `pip install --no-deps -e .`. Dependabot (pip, `/packages/vault-py`) proposes updates to these files.
