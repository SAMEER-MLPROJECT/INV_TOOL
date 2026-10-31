# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers (use GitHub's *Report a vulnerability* /
private security advisory on this repository) rather than opening a public issue. Include steps to reproduce and the
affected version. We aim to acknowledge reports within 7 days.

## Intended deployment

AttackGraph Lens is a prototype for analysts working on their own machine. It has **no authentication**. By default
it binds to `127.0.0.1`; do not expose it to a network without an authenticating reverse proxy and TLS.

Uploaded log files may contain sensitive information (user names, hosts, IP addresses). They are processed in memory;
exported reports are written to `data/exports/`, which is git-ignored. Delete exports you do not need.

## Built-in controls

- Upload allow-list (`.csv`, `.json`, `.jsonl`, `.ndjson`), per-file size limit (default 20 MB), bounded reads,
  record limit, UTF-8 validation.
- Filenames are sanitised (directory components and unsafe characters removed); no user-chosen path is written.
- Files are parsed with the standard-library `csv` and `json` modules only — never executed, imported, unpickled or
  evaluated.
- Neo4j queries are parameterised; labels/relationship types come from fixed enumerations; hop bounds are validated.
- Credentials are read from environment variables (or a git-ignored `.env`), are never returned by the API and are
  excluded from error messages and logs.
- Unexpected errors return a reference id without stack traces; details go to the server log only.
- Graph-expansion limits (hops, search budget, candidate cap, view size) bound resource use.
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.

## Secrets hygiene

Never commit `.env`, keys or database passwords. `.gitignore` excludes them; the repository was scanned for secrets
before publication (see `docs/DEVELOPMENT_LOG.md`).
