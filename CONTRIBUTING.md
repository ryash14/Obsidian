# Contributing to Obsidian

Open an issue describing the problem or intended change before proposing a broad redesign. For a focused fix, a pull request with a reproduction is sufficient.

## Development workflow

1. Read the README prerequisites and configure only local, private credentials.
2. Create a branch for one behavior change. Preserve existing public interfaces unless the change explains the migration.
3. Add a regression case for changed behavior when the repository has a test harness. Use synthetic or public data.
4. Run the relevant checks and record their output in the pull request.
5. Stage named files with `git add path/to/file`; inspect `git diff --cached` before committing.

## Checks

```bash
node --check functions/relay-api/src/main.js
node --check functions/relay-api/src/envelope.js
```

These are verification instructions, not a claim that every application integration is continuously tested. Provider-backed checks can require credentials, downloads or quota; identify those requirements in the pull request.

## Pull request details

Explain the triggering problem, the resulting behavior, the tests performed and any remaining limits. Update the README or supporting documentation when configuration, data contracts or deployment requirements change. Keep generated caches, credentials, uploaded documents, model weights and local database state out of unrelated changes.

## Reporting problems

Include runtime versions, the command or request used, expected and actual output, and a minimal sanitized reproduction. Follow [SECURITY.md](SECURITY.md) for vulnerabilities and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) in discussions.
