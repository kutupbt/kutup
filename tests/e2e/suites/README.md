# Browser suites

Each `<suite>.txt` lists the Playwright specs of one browser suite, one path per
line, relative to `tests/e2e`. A `#` starts a comment.

CI runs a suite with `scripts/gate.sh browser <suite>`, and so does a local
pre-merge run, so the list cannot drift between them. A new spec goes into the
right file here, not into `.github/workflows/ci.yml`.

| Suite | CI job |
| --- | --- |
| `mail.txt` | Mail browser specs: Mail step |
| `contacts.txt` | Mail browser specs: Contacts step |
| `pass.txt` | Mail browser specs: Pass step |
| `calendar.txt` | Mail browser specs: Calendar step |
| `account.txt` | Mail browser specs: Account step |
| `office.txt` | Mail browser specs: Office collaboration step |
| `mail-domains.txt` | Mail custom domains browser specs (`scripts/test-mail-domains-browser.sh`, on the mail gate's stack) |
| `chat-backup.txt` | Clean-browser Chat backup recovery |
