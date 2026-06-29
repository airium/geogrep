# Development

This document collects development rules that should be followed by maintainers
and coding agents.

## Commit Messages

Use Conventional Commits:

```text
<type>(<optional scope>): <description>
```

Rules:

- Use an allowed type such as `feat`, `fix`, `refactor`, `perf`, `style`,
  `test`, `docs`, `build`, `ops`, or `chore`.
- Use an optional scope for the affected area, for example `loader`, `convert`,
  `web`, `release`, or `development`.
- Write the description in imperative present tense.
- Do not capitalize the first description word.
- Do not end the subject with a period.
- Use `!` before `:` for breaking changes and explain them with a
  `BREAKING CHANGE:` footer.

Examples:

```text
fix(loader): reject oversized SRS string lengths
docs(development): add commit message guidance
build(release): bump version to 0.3.1
```

When a task asks for one commit per fix, keep each commit focused and include
the implementation, focused tests, and related documentation or changelog entry
for that specific fix.

## Signing

Commits should be GPG signed with the repository user's configured Git signing
setup.

```bash
git commit -S
```

If signing requires a passphrase and the local GPG agent cache is expired, stop
and ask the user to unlock the key before retrying the commit.
