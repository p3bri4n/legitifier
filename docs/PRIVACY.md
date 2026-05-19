# Privacy and GDPR considerations

legitifier processes personal data within the meaning of GDPR (Article 4):
- GitHub usernames (direct identifiers)
- Verdicts attributed to users or repositories (potentially defamatory)
- A pseudonymous machine identifier in the feedback table

## Where the data lives

- **Locally on your machine**: `~/.legitifier/scans.db` and `~/.legitifier/cache.db`.
- **Nowhere else by default**: legitifier never sends data to Anthropic, the
  legitifier maintainers, or any third party.

## When YOU become a data controller

If you publish an export (`legitifier export dataset.jsonl` shared on HuggingFace,
GitHub, or anywhere public), you become the data controller under GDPR. You are
then responsible for:
- **Legal basis**: typically "legitimate interest" for fraud prevention (Recital 47).
- **Subjects' rights**: handle access, rectification, erasure, objection.
- **Accuracy**: a SCAM verdict on a real person can be defamatory. Manual review
  required before publication.
- **Minors**: GitHub users can be 13+. No way to filter — mention this limitation.

We recommend publishing only with `--anonymize`.

## Anonymizing exports

```bash
legitifier export dataset.jsonl --anonymize
```

Replaces GitHub logins with `sha256(login + salt)[:16]`. The salt is generated
and stored once in `~/.legitifier/anonymize_salt` (mode 0600).

## Erasing data

```bash
legitifier forget <github-login>
```

Removes the login from `scans`, `feedback`, `reputation` tables. Destructive.

For deeper cleanup (scans where the login appears as stargazer/PR author of
someone else's repo):

```bash
legitifier forget <github-login> --deep
```

## Retention

No enforced retention. Set your own:
```bash
sqlite3 ~/.legitifier/scans.db "DELETE FROM scans WHERE scanned_at < date('now', '-1 year')"
```

## Contact

Via SECURITY.md channel.
