---
name: pre-launch-security-check
description: Pre-launch security check for any app - web, mobile, desktop, browser extension, API backend or published package. Use it before launching, releasing, deploying or sharing an app, and whenever someone asks if their API keys or secrets might be exposed, even if they never say "security". It scans source, build output, git history and the live server, reports what it finds, then fixes what it can.
---

# Pre-launch security check

Small apps rarely get hurt by clever attacks. They get hurt by a secret key shipped inside the app, an `.env` sitting in git history, a server that hands out `/.env`, a database left open to everyone, or an API key with no spending cap. Bots scan for all of these from the moment a site, repo or app goes public, so "nobody knows about my app yet" protects nothing. This skill finds those problems, reports them, then fixes what can be fixed in code.

The scanner is `scripts/scan.py` in this skill's folder. It needs only Python 3.8+ and no packages, it never prints full secret values, and it exits with code 1 if it finds anything HIGH.

## The mental model (explain it to the user when it matters)

- **Whatever ships to users is public.** That means browser JS bundles, mobile apps (`.apk`/`.ipa` files are just zip archives), desktop apps (Electron `app.asar`, Tauri and other native binaries, whose strings are readable), browser extensions, CLI tools and libraries published to npm or PyPI, and public Docker images. Obfuscation only slows people down. A secret key can only live on a server the user controls.
- **Build tools put prefixed env vars into the bundle on purpose.** `VITE_` (plus electron-vite's `MAIN_VITE_` / `PRELOAD_VITE_` / `RENDERER_VITE_`), `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_`, `NUXT_PUBLIC_` and similar are copied into shipped code as plain text. Some tools put the whole `.env` into the app: `flutter_dotenv` (when `.env` is listed as an asset), `react-native-config`, and a `define: {'process.env': process.env}` line in the build config. A gitignored `.env` doesn't help in any of these cases.
- **Moving a key to a backend is only half the fix.** If the backend or serverless endpoint that calls OpenAI has no auth and no rate limit, anyone can spend through it. The key is hidden, but the bill is still wide open.
- **Deleting a leaked key from code does nothing.** Someone may already have copied it. The fix is rotating the key (issue a new one, revoke the old one).
- **Some keys are public by design** and are fine to ship: Stripe/Clerk `pk_...`, Supabase `sb_publishable_...` or the legacy anon key (safe only if Row Level Security is on), Firebase web config (safe only if security rules are strict), Mapbox `pk.`, a restricted Google Maps browser key, Sentry DSN, Algolia search-only key, reCAPTCHA site key. Don't raise false alarms about these. Their safety depends on the server-side rules, so check those instead.

## Workflow

### 0. Get oriented

Work out what kind of app this is (it may be several: a web frontend plus an API, a mobile app plus Firebase), its build and release commands, which paid or privileged services it uses (LLM APIs, payments, email, databases, cloud), and where the backend is deployed. When looking at `.env` files, read variable names only (for example `cut -d= -f1 .env`). Never print secret values into the conversation; the scanner redacts them for the same reason.

Ask the user only for what you can't find yourself: the deployed URL(s), and whether the repo has ever been public or shared.

### 1. Source scan

`python3 <skill-dir>/scripts/scan.py source <repo>`

This covers `.env` files (secrets behind public prefixes, env files not gitignored or already tracked), hardcoded keys, and risky settings. Frameworks covered: Express, FastAPI, Django, Flask, Electron, Firebase rules, Dockerfiles, Flutter and React Native config. The scanner can't tell which files ship and which stay on a server, so decide per finding: a key in client code must be fixed before launch, while a key hardcoded in server code in a private repo should be moved to an env var.

### 2. Build, then scan what actually ships

Run the production build, then scan the output:

`python3 <skill-dir>/scripts/scan.py client <paths>`

The scanner opens archives itself, including nested ones (`.asar`, `.apk`, `.aab`, `.ipa`, `.zip`, `.crx`, `.whl`, `.tgz`, ...), and reads strings out of compiled binaries.

| App type | Scan these |
|---|---|
| Web SPA (Vite, CRA, Vue, Svelte, Angular) | `dist/` or `build/` |
| Next.js | `.next/static/` (plus `out/` for static export). `.next/server/` stays on the server |
| Nuxt / SvelteKit | `.output/public/` / `.svelte-kit/output/client/` |
| Electron | unpacked app from `electron-builder --dir`, which contains `app.asar` (`find . -name app.asar -not -path "*/node_modules/*"`) |
| Tauri / other native desktop | the built app or binary under `src-tauri/target/release/` (or the equivalent) |
| React Native / Expo / Flutter / native mobile | the release `.apk` / `.aab` / `.ipa` (or `npx expo export` output). Flutter `--dart-define` values are compiled in |
| Browser extension | the built extension folder or its `.zip` / `.crx` |
| npm / PyPI package, CLI | the `npm pack` tarball or the wheel/sdist from `python -m build` |

Installers like `.dmg`, `.msi` and NSIS `.exe` are compressed, so scan the unpacked app instead. This step catches what the source scan can't: keys injected at build time from CI or shell env vars, env files copied into the package, and source maps. If the build fails or takes too long, say so in the report and don't call the build output clean. If the app is a public Docker image, also check `docker history --no-trunc <image>` for secrets in ENV/ARG layers.

### 3. Git history

`python3 <skill-dir>/scripts/scan.py git <repo>`

This scans every commit on every branch. A key committed once and deleted later is still in history; if the repo was ever pushed somewhere public or shared, treat that key as leaked.

### 4. Live probe (only servers the user owns)

`python3 <skill-dir>/scripts/scan.py probe https://api.their-domain.com`

This checks whether `/.env` or `/.git` can be downloaded, whether a debug error page shows (Django, Werkzeug, Rails), whether Spring `/actuator/env` or Go `pprof` is exposed, whether API docs are public, and whether the site runs on plain HTTP. Never probe sites the user doesn't control. If nothing is deployed yet, skip this step and list it under "Not checked".

### 5. Manual review: read the code for what a scanner can't judge

**Any backend, serverless function or edge function:**
- Every endpoint that costs money or touches user data requires auth. List any endpoint that is intentionally public.
- Endpoints that spend money (LLM, email, SMS) have per-user or per-IP rate limits, an input size cap, and server-side limits like `max_tokens`. Without these, hiding the key doesn't protect the bill.
- Ownership checks: `GET /items/{id}` must confirm the item belongs to the caller. Otherwise users can read each other's data by changing the ID.
- CORS lists real origins, never `*` together with credentials.
- In production, debug mode is off and errors don't return stack traces. Public API docs are a deliberate choice.
- Webhooks (Stripe and others) verify their signatures.
- File uploads check type and size, and are stored where they can't be executed or listed.
- Secrets come from the platform's environment settings or a secret store, not from committed files.

**Backend-as-a-service (Supabase, Firebase, cloud storage):**
- Supabase: RLS is enabled on every table the client can reach. The client has only the publishable/anon key, and `sb_secret_...` / `service_role` keys stay server-side. Prefer the newer `sb_` keys; the legacy JWT keys are being phased out.
- Firebase: Firestore, Realtime Database and Storage rules require auth and ownership, with no leftover "test mode" rules. The scanner reads rule files in the repo, but the deployed rules can differ, so have the user confirm in the console.
- Cloud buckets (S3, GCS, R2): user uploads are not publicly listable, and any public bucket is public on purpose.

**Client apps (web, mobile, desktop, extensions):**
- No secrets anywhere in shipped code. Paid or privileged calls go through the backend.
- If users bring their own API key, store it with the platform's secure storage (Keychain, Android Keystore, Electron `safeStorage`) and never log it.
- Electron: `contextIsolation` on, `nodeIntegration` off, `sandbox` on. The preload script exposes a few named functions, never all of `ipcRenderer`. `ipcMain` handlers validate their inputs. Navigation and `window.open` are restricted, and `shell.openExternal` only receives validated `https://` URLs.
- Web: user content is rendered without `dangerouslySetInnerHTML` / `v-html` on untrusted data, and a Content Security Policy is set if feasible.
- Browser extensions: request the fewest permissions and host permissions they need.

**Dependencies (optional):** if available, run `npm audit --omit=dev`, `pip-audit`, or the ecosystem's equivalent, and report only critical or high issues in shipped dependencies.

### 6. Spend caps and key permissions (the user does this in each dashboard)

For every paid service found, tell the user exactly what to check. Provider settings change over time, so describe what to look for and have the user confirm it in the dashboard rather than stating what a provider currently offers:
- Is there a **hard limit** that stops spending, or only an email alert? An alert doesn't stop anything. If only alerts exist, backend rate limiting is the real cap.
- Payment providers like Stripe have no spending cap. The equivalent is a **restricted key** with only the permissions the backend needs.
- Use least-privilege keys wherever offered (for example a send-only email key, or a read-only database user), and one key per project or environment, so a single leak doesn't expose everything.

## Report

Write the report in the user's language. Merge duplicates: the same key found in `.env`, the bundle and git history is one problem with several locations. Never include full secret values.

```
# Pre-launch security check: <project>
Verdict: BLOCKED (must fix before launch) / OK TO LAUNCH, FIXES RECOMMENDED / NO BLOCKERS FOUND

## Must fix before launch
For each: what - where - why it matters (one line) - fix - who fixes it (I can fix / you must do it in a dashboard)

## Should fix

## Minor (one line each)

## Your dashboard checklist
Keys to rotate (named exactly), spend caps to set, rules/RLS to confirm, ...

## Not checked
What was skipped and why (no deployment URL, build failed, no git repo, ...)
```

Severity guide: anything shipped to users, served publicly, open to everyone (database rules), or present in git history is HIGH. Risky config is MEDIUM unless the scanner says HIGH. Dev-only issues are LOW.

## Fixing (only after the report)

Ask which items to fix. The default is every code-level HIGH and MEDIUM item. Work in this order:

1. **Rotation comes first, and the user does it.** List exactly which keys to rotate and where. Do it now, not after the code changes, because the old key is already exposed.
2. **Move secret calls behind a server the user controls**: their backend, or a serverless/edge function (Supabase Edge Functions, Vercel/Netlify/Cloudflare functions, Firebase Cloud Functions). The server reads keys from its environment. Add auth and rate limiting to that endpoint in the same change; otherwise it becomes an open proxy.
3. Rename env vars to drop public prefixes, take secrets out of anything bundled (client env files, Flutter assets, react-native-config `.env`, build `define`), and add `.env*` to `.gitignore` and `.dockerignore` while keeping `!.env.example` tracked.
4. Harden config: database rules / RLS, CORS, debug flags, static file roots, Electron settings.
5. **Re-run the scans** that found each issue: rebuild, then run the client scan again. A fix isn't done until the rescan is clean.

Never do these without explicit consent: rewriting git history (filter-repo/BFG) or force-pushing (both are destructive, and neither undoes a leak; rotation is the real fix), deleting files outside the project, deploying rule changes, calling provider APIs with the user's keys, or printing secret values.

## Prevention: CLAUDE.md rule

If the project's `CLAUDE.md` (or `AGENTS.md`) has no rule about secrets, offer to add this block (in the language the file already uses). It prevents the classic failure where an AI assistant adds a `VITE_` prefix to a key just to make a feature work:

```
## Secrets
- Never put secret keys in anything that ships to users: web bundles, mobile apps, desktop apps (Electron main process included), extensions, published packages, public images. Public-prefixed env vars (VITE_, NEXT_PUBLIC_, REACT_APP_, EXPO_PUBLIC_, ...) and bundled .env files are public.
- Paid or privileged API calls go through our backend or a serverless function, and that endpoint needs auth + rate limiting.
- If something only works by exposing a secret to the client, stop and ask instead of making it work.
- Never print secret values in chat or logs.
```
