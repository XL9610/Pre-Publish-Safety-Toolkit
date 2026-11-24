# Pre-Publish Safety Toolkit

Catch leaked API keys, open databases and risky config before you publish. Packaged as a [Claude](https://claude.com) skill, with a scanner you can also run on its own.

## pre-launch-security-check

Catches the mistakes that actually burn small apps, before your users (or bots) find them:

- **Secret keys shipped to users**: `VITE_` / `NEXT_PUBLIC_` / `EXPO_PUBLIC_` env vars, keys hardcoded in frontend code, `.env` files bundled into the app, the whole `process.env` injected by a build config
- **Secrets in git history**, including `.env` files that were committed once and deleted later
- **Servers that leak**: downloadable `/.env` or `/.git`, Django/Werkzeug/Rails debug pages, Spring `/actuator/env`, Go `pprof`
- **Open data**: Firebase rules left in test mode, Realtime Database open to everyone, Supabase service keys in the client
- **Risky config**: wildcard CORS, debug mode, static servers rooted at the project folder, Electron `nodeIntegration` / `contextIsolation`, secrets in Dockerfile `ENV`/`ARG`
- **No spending cap**: a checklist for every paid API the app uses

It works with web apps, mobile apps (`.apk` / `.aab` / `.ipa`), desktop apps (Electron `app.asar`, Tauri and native binaries), browser extensions, API backends and published packages (npm, PyPI). It opens archives itself, including nested ones, and reads strings out of compiled binaries.

The skill runs a scan, writes a report (must fix / should fix / your dashboard checklist / not checked), then fixes what can be fixed in code after you choose. Key rotation always comes first, and it's yours to do.

### Install

**Claude Code**

```bash
git clone https://github.com/XL9610/Pre-Publish-Safety-Toolkit.git
mkdir -p ~/.claude/skills
cp -r Pre-Publish-Safety-Toolkit/pre-launch-security-check ~/.claude/skills/
```

Then ask something like *"check my app before launch"* or *"did I leak any API keys?"*.

**Claude apps:** zip the `pre-launch-security-check` folder and upload it as a custom skill in Claude's settings.

### Use the scanner on its own

The scanner needs only Python 3.8+ (standard library only). It never prints full secret values.

```bash
S=pre-launch-security-check/scripts/scan.py
python3 $S source  path/to/repo              # .env files, hardcoded keys, risky config
python3 $S client  dist/ release/app.apk     # whatever ships to users
python3 $S git     path/to/repo              # every commit on every branch
python3 $S probe   https://api.your-domain   # only servers you own
```

Add `--json` for machine-readable output. The exit code is 1 when anything HIGH is found, so the scanner can gate a CI job.

### Limits

These are heuristics, not a professional audit. The scanner can't see deployed database rules, provider billing settings, or your auth logic; the skill covers those with a manual checklist. Only probe servers you own.

### Tests

```bash
python -m unittest discover -s tests -v
```

The tests build fake projects for each stack (web, Electron, mobile, packages, Django/Flask/FastAPI/Express, Firebase, Docker) using random fake keys. They check that every planted problem is found, that public-by-design keys and placeholders stay quiet, and that no full secret ever appears in the output.
