# Contributing to Abyss

Thanks for considering a contribution. This is a small, focused educational
project, so the bar for "good contribution" is mostly: does it stay honest
about what it does, and does it stay within scope?

## Setup

```bash
git clone https://github.com/<your-username>/abyss.git
cd abyss
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Before opening a PR

- Run the CLI and web dashboard locally against `127.0.0.1` or
  `scanme.nmap.org` and confirm your change actually works — this project
  has caught real bugs (formatting issues, false-404s) simply by running
  things rather than just reading the code.
- Keep new engines/modules isolated in `abyss/core/` the way existing ones are,
  so the CLI and web dashboard can both use them without duplicating logic.
- If you're documenting a limitation (e.g. "this doesn't do X because Y"),
  keep that comment in the code — the project's whole ethos is being honest
  about what it can and can't do, rather than overselling itself.

## Scope guardrails

Please open an issue to discuss before adding:
- Anything that actively attempts authentication/login against a target
  (credential brute-forcing, default-password testing, etc.) — this is
  deliberately out of scope; see the README's "Scope, honestly" section.
- A hardcoded CVE/vulnerability database — see `abyss/core/advisories.py`
  for why this project generates search links instead.
- A full packet-capture/traffic-analysis engine — that's a different project.

Bug fixes, new protocol probes (banner detection for more services),
UI polish, and documentation improvements are all very welcome.

## Code style

Plain, readable Python. Type hints are welcome but not required. Comments
explaining *why* (especially safety/scope tradeoffs) are more valuable here
than comments explaining *what*.
