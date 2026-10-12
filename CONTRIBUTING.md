# Contributing

Thanks for your interest in improving VulnHunter.

> **Where to contribute.** This is the maintained fork of
> [Capital One's VulnHunter](https://github.com/capitalone/vulnhunter)
> (Apache-2.0), focused on harness portability, sandboxed exploit validation,
> and measured-impact PoCs. Contribute here. Changes that are relevant to
> every harness are also welcome upstream — PRs to
> [`capitalone/vulnhunter`](https://github.com/capitalone/vulnhunter) are
> encouraged for those.

## Ground rules

- Be respectful and constructive.
- Assume you are authorized to scan whatever you point the scanner at — there is no permission gate.
- Do not include real, unpublished vulnerability data for third-party systems in
  the benchmark corpus you commit — use synthetic entries or public,
  deliberately-vulnerable apps (see
  `harness/local_harness/benchmark/ground_truth/README.md`).

## Development setup

Each Python component is a self-contained subtree with its own `pyproject.toml`;
there is no root package. Install and test whichever component you're changing:

```bash
git clone https://github.com/nealbridges/VulnHunter.git
cd VulnHunter

# dev harness (batch + benchmark tooling)
cd harness          && python -m pip install -e ".[dev]" && python -m pytest tests/ --cov=local_harness
# the fix skill's helper package
cd vulnhunter-fix   && python -m pip install -e ".[dev]" && python -m pytest -q
# the headless runtime agent
cd vulnhunter-agent && python -m pip install -e ".[dev]" && python -m pytest -q
```

The `vulnhunt/`, `vulnhunt-fix-verify/`, and `vulnhunter-fix/` skills are
prompt-only (Markdown) and harness-portable: copy them into your agent harness's
skills directory, or run `./install.sh` from the repo root. The installer defaults
to `~/.claude/skills`; set `VULNHUNT_SKILLS_DIR` to install somewhere else.

## Pull requests

1. Fork the repo and create a topic branch.
2. Make your change with a clear commit message describing the "why".
3. Keep the harness tests green and coverage steady.
4. Open a PR describing the change and how you validated it.
5. If your change is relevant to every harness and you're comfortable with it,
   consider offering it upstream too — see the note at the top.

## Reporting bugs

Open a GitHub issue for functional bugs. For security issues in the tool itself,
follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
