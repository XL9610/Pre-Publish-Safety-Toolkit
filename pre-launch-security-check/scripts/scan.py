#!/usr/bin/env python3
"""pre-launch-security-check scanner. Python 3.8+, standard library only. Never prints full secret values.

  python3 scan.py source <repo>        env files, public-prefixed secrets, hardcoded keys, risky config
  python3 scan.py client <path>...     whatever ships to users: build folders, app.asar, .apk/.aab/.ipa,
                                       .zip/.whl/.tgz packages, compiled binaries (archives are opened, nested too)
  python3 scan.py git <repo>           every commit on every branch: secrets / env files ever committed
  python3 scan.py probe <base-url>...  a server YOU own: /.env, /.git, debug pages, exposed admin endpoints

Add --json for machine-readable output. Exit code 1 if any HIGH finding, else 0.
"""
import argparse
import base64
import io
import json
import os
import re
import struct
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile

SEVS = ["HIGH", "MEDIUM", "LOW", "INFO"]
MAX_TEXT = 30 * 1024 * 1024      # text files larger than this are skipped
MAX_BLOB = 512 * 1024 * 1024     # binaries / archive members larger than this are skipped
SHIPPED = " - shipped to every user"

# ----------------------------------------------------------------------------- secret formats
# id, regex, label, severity, must look random (filters kebab-case identifiers and words)
SECRET_PATTERNS = [
    ("sk-live", r"\b[rs]k_live_[0-9A-Za-z]{20,}", "Live secret key (Stripe/Clerk style sk_live_/rk_live_)", "HIGH", False),
    ("sk-test", r"\b[rs]k_test_[0-9A-Za-z]{20,}", "Test-mode secret key (Stripe/Clerk style)", "MEDIUM", False),
    ("stripe-webhook", r"\bwhsec_[0-9A-Za-z+/=]{20,}", "Stripe webhook signing secret", "HIGH", False),
    ("anthropic", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key", "HIGH", True),
    ("sk-dash", r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-|or-v1-)?[A-Za-z0-9_\-]{20,}",
     "sk- style API key (OpenAI, OpenRouter, DeepSeek, ...)", "HIGH", True),
    ("groq", r"\bgsk_[A-Za-z0-9]{40,}", "Groq API key", "HIGH", True),
    ("xai", r"\bxai-[A-Za-z0-9]{40,}", "xAI API key", "HIGH", True),
    ("replicate", r"\br8_[A-Za-z0-9]{30,}", "Replicate API token", "HIGH", True),
    ("huggingface", r"\bhf_[A-Za-z0-9]{30,}", "Hugging Face token", "HIGH", True),
    ("resend", r"\bre_[A-Za-z0-9]{6,}_[A-Za-z0-9]{16,}", "Resend API key", "HIGH", True),
    ("sendgrid", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", "SendGrid API key", "HIGH", False),
    ("mailgun", r"\bkey-[0-9a-f]{32}\b", "Mailgun API key", "HIGH", True),
    ("supabase-secret", r"\bsb_secret_[A-Za-z0-9_\-]{20,}", "Supabase secret key (bypasses RLS)", "HIGH", False),
    ("supabase-pat", r"\bsbp_[A-Za-z0-9]{30,}", "Supabase personal access token", "HIGH", False),
    ("aws-key-id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key ID", "HIGH", True),
    ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})", "GitHub token", "HIGH", False),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9_\-]{20,}", "GitLab token", "HIGH", False),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b", "npm token", "HIGH", True),
    ("pypi-token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", "PyPI token", "HIGH", False),
    ("slack-token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", "Slack token", "HIGH", False),
    ("slack-webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}", "Slack webhook URL", "MEDIUM", False),
    ("discord-webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{50,}",
     "Discord webhook URL", "MEDIUM", False),
    ("telegram-bot", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b", "Telegram bot token", "HIGH", False),
    ("mapbox-secret", r"\bsk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}", "Mapbox secret token", "HIGH", False),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}",
     "Google API key (Firebase/Maps browser keys are public if restricted; Gemini keys are secret)", "MEDIUM", False),
    ("gcp-service-account", r"\"type\"\s*:\s*\"service_account\"", "Google service account credentials", "HIGH", False),
    ("private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", "Private key", "HIGH", False),
    ("db-url", r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:/@'\"`]+:[^\s@'\"`]+@[^\s'\"`<>]+",
     "Database/queue URL with password", "HIGH", False),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", "JWT", "LOW", False),
]
SECRET_RX = [(i, re.compile(r), l, s, rnd) for i, r, l, s, rnd in SECRET_PATTERNS]
PLACEHOLDER = re.compile(r"x{4,}|your[_\-]?|example|placeholder|dummy|replace[_\-]?me|changeme|redacted|"
                         r"\*{3,}|\.{3}|<|\$\{|\{\{|%\(", re.I)
LOCAL_DB = re.compile(r"@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|redis|mongo)(?:[:/]|$)")
TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|__mocks__|testdata)/|(?:^|/)test_[^/]*$|"
                       r"_test\.[a-z]+$|\.(?:test|spec)\.[a-z]+$", re.I)

# ----------------------------------------------------------------------------- risky configuration
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".astro", ".html", ".htm"}
CONFIG_RISKS = [  # id, regex, severity, message, file kind (see file_kind)
    # build tools / JS
    ("define-process-env", r"['\"]process\.env['\"]\s*:\s*(?:JSON\.stringify\(\s*)?process\.env\b", "HIGH",
     "Build config injects the whole process.env into the client bundle - every env var on the build machine ships", "js"),
    ("dotenv-in-js", r"require\(\s*['\"]dotenv['\"]\s*\)|from\s+['\"]dotenv['\"]|import\s+['\"]dotenv/config['\"]", "INFO",
     "dotenv: fine on a server; in client or desktop code it means keys are either missing in production or a .env ships with the app", "js"),
    ("cors-any-js", r"\bcors\(\s*\)", "MEDIUM", "cors() with no options allows any origin; pass an explicit origin list", "js"),
    ("tls-verify-off-js", r"rejectUnauthorized\s*:\s*(?:false|!1)\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", "MEDIUM",
     "TLS certificate verification disabled", "js"),
    ("static-root-js", r"express\.static\(\s*(?:['\"]\.?/?['\"]|__dirname)\s*\)", "HIGH",
     "Static file server rooted at the project folder can serve .env and source files", "js"),
    # Electron
    ("electron-nodeIntegration", r"nodeIntegration\s*:\s*(?:true|!0)\b", "MEDIUM",
     "Electron nodeIntegration is on: any XSS in the page becomes code execution on the user's machine", "js"),
    ("electron-contextIsolation-off", r"contextIsolation\s*:\s*(?:false|!1)\b", "MEDIUM",
     "Electron contextIsolation is off: page scripts can reach preload/Node internals", "js"),
    ("electron-sandbox-off", r"\bsandbox\s*:\s*(?:false|!1)\b", "LOW", "Electron renderer sandbox disabled", "js"),
    ("electron-webSecurity-off", r"webSecurity\s*:\s*(?:false|!1)\b", "MEDIUM", "Electron webSecurity disabled (same-origin policy off)", "js"),
    ("electron-insecure-content", r"allowRunningInsecureContent\s*:\s*(?:true|!0)\b", "MEDIUM", "Loads http content inside https pages", "js"),
    ("electron-remote-module", r"enableRemoteModule\s*:\s*(?:true|!0)\b|@electron/remote", "LOW",
     "Electron remote module gives pages main-process power; prefer narrow IPC", "js"),
    ("electron-expose-ipcRenderer", r"exposeInMainWorld\s*\([^;]{0,300}?\bipcRenderer\b(?!\s*\.)", "MEDIUM",
     "Electron preload exposes the whole ipcRenderer to the page; expose a few named functions instead", "js"),
    ("electron-openExternal", r"shell\.openExternal\s*\(", "INFO", "Make sure only validated https:// URLs reach shell.openExternal", "js"),
    ("http-loadURL", r"loadURL\s*\(\s*['\"`]http://(?!localhost|127\.0\.0\.1)", "MEDIUM", "Window loads a remote page over plain http", "js"),
    # Python web frameworks
    ("static-root-py", r"StaticFiles\(\s*directory\s*=\s*['\"](?:\.|\./)?['\"]", "HIGH",
     "StaticFiles rooted at the project folder can serve .env and source files", "py"),
    ("cors-wildcard-py", r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", "MEDIUM",
     "CORS allows any origin; list your real origins (never '*' together with credentials)", "py"),
    ("cors-all-django", r"CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True", "MEDIUM", "django-cors-headers allows any origin", "py"),
    ("cors-any-flask", r"\bCORS\(\s*app\s*\)", "MEDIUM", "flask-cors with default settings allows any origin", "py"),
    ("fastapi-debug", r"FastAPI\([^)]*\bdebug\s*=\s*True", "MEDIUM", "debug=True sends stack traces to clients", "py"),
    ("django-debug", r"(?m)^DEBUG\s*=\s*True\b", "MEDIUM", "Django DEBUG = True must be off in production (shows settings and stack traces)", "py"),
    ("flask-debug", r"\.run\([^)]*\bdebug\s*=\s*True", "MEDIUM",
     "Flask debug mode (debug=True passed to run) exposes the interactive debugger: anyone who triggers an error can run code", "py"),
    ("allowed-hosts-any", r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]", "LOW", "ALLOWED_HOSTS with '*' accepts any Host header", "py"),
    ("hardcoded-secret-key", r"(?m)^\s*(?:app\.)?(?:config\[['\"])?SECRET_KEY(?:['\"]\])?\s*=\s*['\"][^'\"]{8,}['\"]", "MEDIUM",
     "SECRET_KEY is hardcoded (it signs sessions/cookies); load it from the environment", "py"),
    ("tls-verify-off-py", r"\bverify\s*=\s*False", "MEDIUM", "TLS certificate verification disabled", "py"),
    ("dev-reload", r"\breload\s*=\s*True", "LOW", "Auto-reload is for development; keep it out of the production start command", "py"),
    # Firebase security rules
    ("firebase-open-rules", r"allow\s+[a-z, ]+?\s*(?::\s*if\s+true\s*)?;", "HIGH", "Security rule lets anyone read/write this data", "rules"),
    ("firebase-test-mode", r"allow\s+[a-z, ]+:\s*if\s+request\.time\s*<\s*timestamp\.date", "HIGH",
     "Test-mode rule: the data is open to anyone until the date in the rule", "rules"),
    ("firebase-rtdb-open", r"\"\.(?:read|write)\"\s*:\s*(?:true|\"true\")", "HIGH", "Realtime Database rule open to everyone", "rules"),
    # Containers
    ("docker-secret-env", r"(?im)^[ \t]*(?:ENV|ARG)[ \t]+[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE)[A-Z0-9_]*\b",
     "MEDIUM", "Secret passed via ENV/ARG is stored in the image; inject it at runtime or use build secrets", "docker"),
    ("docker-copy-env", r"(?im)^[ \t]*(?:COPY|ADD)[ \t]+(?:--\S+[ \t]+)*\S*\.env\b", "HIGH",
     ".env copied into the image - anyone with the image can read it", "docker"),
    # Mobile
    ("flutter-env-asset", r"(?m)^\s*-\s*['\"]?\.env['\"]?\s*$", "HIGH",
     "flutter_dotenv: .env listed as an asset is bundled into the app - only public values may go in it", "pubspec"),
    ("rn-env-baked", r"\"react-native-(?:config|dotenv)\"", "MEDIUM",
     "react-native-config/dotenv bake .env values into the app at build time - keep only public values in that .env", "pkgjson"),
]
CONFIG_RX = [(i, re.compile(r), s, m, k) for i, r, s, m, k in CONFIG_RISKS]

# ----------------------------------------------------------------------------- env files and walking
PUBLIC_PREFIXES = ("VITE_", "MAIN_VITE_", "PRELOAD_VITE_", "RENDERER_VITE_", "NEXT_PUBLIC_", "REACT_APP_", "EXPO_PUBLIC_",
                   "NUXT_PUBLIC_", "PUBLIC_", "GATSBY_", "VUE_APP_", "STORYBOOK_", "PARCEL_PUBLIC_", "SNOWPACK_PUBLIC_")
SECRET_NAME = re.compile(r"SECRET|PRIVATE|PASSW|TOKEN|SERVICE_ROLE|API_?KEY|ACCESS_KEY|CREDENTIAL|_KEY$", re.I)
PUBLIC_OK_NAME = re.compile(r"PUBLISHABLE|ANON_KEY|PUBLIC_KEY|SITE_KEY|MEASUREMENT_ID|_DSN$|_URL$|_HOST$", re.I)
ENV_NAME = re.compile(r"^\.env(\..+)?$|^.+\.env$|^\.envrc$")
ENV_TEMPLATE = re.compile(r"\.(example|sample|template|dist|defaults)$", re.I)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
             ".idea", ".vscode", ".cache", ".turbo", ".parcel-cache", "coverage", ".nyc_output", "Pods", "vendor",
             ".dart_tool", ".gradle", "DerivedData", ".expo", "bower_components", "site-packages"}
BUILD_DIRS = {"dist", "build", "out", "release", "dist-electron", ".next", ".nuxt", ".output", ".svelte-kit", ".vercel",
              ".netlify", "target"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".icns", ".bmp", ".tif", ".tiff", ".svgz", ".woff",
            ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov", ".m4a", ".aac", ".flac",
            ".mkv", ".avi", ".psd", ".pak", ".dat", ".bin", ".blockmap", ".dmg", ".msi", ".pdf"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock", "bun.lockb",
             "go.sum", "Cargo.lock", "Podfile.lock", "pubspec.lock", "composer.lock", "Gemfile.lock"}
ZIP_EXT = {".zip", ".apk", ".aab", ".ipa", ".jar", ".war", ".xpi", ".crx", ".vsix", ".whl", ".appx", ".msix", ".nupkg", ".egg"}
TAR_SUFFIXES = (".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".crate")
PRINTABLE = re.compile(rb"[\x20-\x7e]{12,}")


class Report:
    def __init__(self):
        self.items, self.seen = [], set()

    def add(self, sev, check, where, msg, snippet="", key=None):
        k = key or (check, where, snippet)
        if k not in self.seen:
            self.seen.add(k)
            self.items.append({"severity": sev, "check": check, "where": where, "message": msg, "snippet": snippet})


def looks_random(s):
    body = re.sub(r"^[A-Za-z]+[-_](?:[a-z]+[-_])?", "", s)
    return any(c.isdigit() for c in body) and any(c.isalpha() for c in body) and len(set(body)) >= 10


def jwt_role(tok):
    try:
        seg = tok.split(".")[1]
        return str(json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))).get("role", "?"))
    except Exception:  # noqa: BLE001 - anything undecodable is just "unknown"
        return "?"


def redact(s, pid):
    if pid == "db-url":
        return re.sub(r"(://[^:/@]+:)[^@]+@", r"\1****@", s)[:90]
    if pid in ("private-key", "gcp-service-account"):
        return s
    return s[:4] + "..." if len(s) <= 14 else "%s...%s (%d chars)" % (s[:8], s[-4:], len(s))


def scan_secrets(text, where, rep, sev_fn=lambda s: s, note="", with_line=True, dedupe_by_where=True):
    for pid, rx, label, base_sev, rnd in SECRET_RX:
        for m in rx.finditer(text):
            s = m.group(0)
            if PLACEHOLDER.search(s) or (rnd and not looks_random(s)):
                continue
            sev, lab = base_sev, label
            if pid == "jwt":
                role = jwt_role(s)
                if role == "anon":
                    continue  # Supabase anon key: public by design (needs RLS)
                if role == "service_role":
                    sev, lab = "HIGH", "Supabase service_role JWT (bypasses RLS)"
                else:
                    lab = "JWT (role=%s)" % role
            elif pid == "db-url" and LOCAL_DB.search(s):
                sev, lab = "LOW", label + " (local dev host)"
            snip = redact(s, pid)
            loc = "%s:%d" % (where, text.count("\n", 0, m.start()) + 1) if with_line else where
            rep.add(sev_fn(sev), pid, loc, lab + note, snip, key=(pid, where if dedupe_by_where else "", snip))


def file_kind(name):
    ext = os.path.splitext(name)[1].lower()
    if name == "package.json":
        return "pkgjson"
    if name == "pubspec.yaml":
        return "pubspec"
    if name in ("Dockerfile", "Containerfile") or name.startswith("Dockerfile.") or ext == ".dockerfile":
        return "docker"
    if ext == ".rules" or name == "database.rules.json":
        return "rules"
    if ext in JS_EXT:
        return "js"
    return "py" if ext == ".py" else None


def scan_config(text, where, name, rep):
    kind = file_kind(name)
    for cid, rx, sev, msg, k in CONFIG_RX:
        if k == kind:
            m = rx.search(text)
            if m:
                rep.add(sev, cid, "%s:%d" % (where, text.count("\n", 0, m.start()) + 1), msg, key=(cid, where))


def run_git(repo, *args):
    try:
        return subprocess.run(["git", "-C", repo] + list(args), capture_output=True, text=True, errors="ignore").stdout
    except OSError:
        return ""


def walk(root, skip_build):
    for dp, dns, fns in os.walk(root):
        if "pyvenv.cfg" in fns:
            dns[:] = []
            continue
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS and not (skip_build and d in BUILD_DIRS))
        for fn in sorted(fns):
            yield os.path.join(dp, fn)


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_TEXT:
            return None
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    return None if b"\x00" in data[:8192] else data.decode("utf-8", "ignore")


# ----------------------------------------------------------------------------- source
def check_env_file(repo, rel, name, text, is_git, rep):
    template = bool(ENV_TEMPLATE.search(name))
    has_values = False
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = re.sub(r"^export\s+", "", k).strip(), v.strip().strip("'\"")
        if not v:
            continue
        has_values = True
        tmp = Report()
        scan_secrets(v, "", tmp)
        hit = next((i for i in tmp.items if i["severity"] in ("HIGH", "MEDIUM")), None)
        prefix = next((p for p in PUBLIC_PREFIXES if k.startswith(p)), None)
        where = "%s:%d" % (rel, n)
        if prefix and hit and not template:
            rep.add("HIGH", "public-prefixed-secret", where, "%s = %s. The %s prefix bundles it into the shipped app"
                    % (k, hit["message"], prefix), hit["snippet"])
        elif template and hit and hit["severity"] == "HIGH":
            rep.add("HIGH", "secret-in-env-template", where, "%s in a template file (usually committed) looks like a real %s"
                    % (k, hit["message"]), hit["snippet"])
        elif prefix and SECRET_NAME.search(k) and not PUBLIC_OK_NAME.search(k):
            rep.add("MEDIUM", "public-prefixed-secret-name", where, "%s looks like a secret, and the %s prefix bundles it into "
                    "the shipped app%s - confirm it is public by design"
                    % (k, prefix, " (template: the app is designed this way)" if template else ""))
    if is_git and has_values and not template:
        if run_git(repo, "ls-files", "--", rel).strip():
            rep.add("HIGH", "env-tracked", rel, "This env file is tracked by git - its values are in the repo")
        elif subprocess.run(["git", "-C", repo, "check-ignore", "-q", "--", rel]).returncode == 1:
            rep.add("HIGH", "env-not-ignored", rel, "Not covered by .gitignore - one 'git add .' away from being committed")


def check_docker_context(repo, rel, text, rep):
    if not re.search(r"(?im)^[ \t]*(?:COPY|ADD)[ \t]+(?:--\S+[ \t]+)*\./?[ \t]", text):
        return
    for d in {os.path.dirname(os.path.join(repo, rel)), repo}:
        ignore = os.path.join(d, ".dockerignore")
        if os.path.isfile(ignore) and re.search(r"(?m)^\s*(?:\*\*/)?\.env", read_text(ignore) or ""):
            return
    rep.add("MEDIUM", "docker-context-env", rel, "COPY . copies the whole build context, including any .env, into the image - "
            "add .env* to .dockerignore")


def cmd_source(repo, rep):
    is_git = run_git(repo, "rev-parse", "--is-inside-work-tree").strip() == "true"
    for path in walk(repo, skip_build=True):
        rel, name = os.path.relpath(path, repo).replace(os.sep, "/"), os.path.basename(path)
        ext = os.path.splitext(name)[1].lower()
        if ext in SKIP_EXT or name in LOCKFILES or ext == ".map":
            continue
        text = read_text(path)
        if text is None:
            continue
        if ENV_NAME.match(name):
            check_env_file(repo, rel, name, text, is_git, rep)
            continue
        if TEST_PATH.search(rel):  # fixtures: real keys still matter, risky-looking config does not
            scan_secrets(text, rel, rep, lambda s: "LOW", " - in a test file: fine only if it is fake")
            continue
        scan_secrets(text, rel, rep, note=" - hardcoded in source: if this code ships (web, mobile, desktop, package) "
                     "every user has it; on a server it still lives in the repo")
        scan_config(text, rel, name, rep)
        if file_kind(name) == "docker":
            check_docker_context(repo, rel, text, rep)
    for d in sorted(BUILD_DIRS):
        if os.path.isdir(os.path.join(repo, d)):
            rep.add("INFO", "build-output-present", d + "/", "Not scanned here - run: scan.py client " + os.path.join(repo, d))
    if not is_git:
        rep.add("INFO", "not-git", repo, "Not a git repository - .gitignore checks skipped")


# ----------------------------------------------------------------------------- client (what ships)
def is_archive(name):
    n = name.lower()
    return n.endswith(".asar") or n.endswith(TAR_SUFFIXES) or os.path.splitext(n)[1] in ZIP_EXT


def asar_entries(f):
    """Yield (path, bytes) from an Electron .asar archive (uncompressed, JSON header)."""
    _, header_size, _, json_len = struct.unpack("<4I", f.read(16))
    header = json.loads(f.read(json_len).decode("utf-8"))
    base, stack = 8 + header_size, [("", header)]
    while stack:
        prefix, node = stack.pop()
        for name, e in node.get("files", {}).items():
            p = prefix + "/" + name if prefix else name
            if "files" in e:
                stack.append((p, e))
            elif not e.get("unpacked") and "link" not in e and int(e.get("size", 0)) <= MAX_BLOB:
                f.seek(base + int(e["offset"]))
                yield p, f.read(int(e["size"]))


def archive_entries(name, f):
    n = name.lower()
    if n.endswith(".asar"):
        yield from asar_entries(f)
    elif n.endswith(TAR_SUFFIXES):
        with tarfile.open(fileobj=f, mode="r:*") as tf:
            for m in tf:
                if m.isfile() and m.size <= MAX_BLOB:
                    yield m.name, tf.extractfile(m).read()
    else:
        with zipfile.ZipFile(f) as zf:
            for i in zf.infolist():
                if not i.is_dir() and i.file_size <= MAX_BLOB:
                    yield i.filename, zf.read(i)


def scan_archive(name, f, where, rep, stats, depth):
    try:
        for inner, data in archive_entries(name, f):
            parts = inner.replace("\\", "/").split("/")
            if any(p in SKIP_DIRS for p in parts[:-1]):
                continue
            scan_blob(parts[-1], data, "%s!/%s" % (where, inner), rep, stats, depth + 1)
    except Exception as e:  # noqa: BLE001 - corrupt/encrypted archives: fall back to raw bytes
        rep.add("INFO", "archive-unreadable", where, "Could not open archive (%s); scanned its raw bytes instead" % e)
        f.seek(0)
        scan_binary(f.read(MAX_BLOB), where, rep)


def scan_binary(data, where, rep):
    """Like `strings`: pull printable runs out of a binary and look for keys in them."""
    text = "\n".join(m.group().decode("ascii") for m in PRINTABLE.finditer(data))
    scan_secrets(text, where, rep, note=SHIPPED + " (found inside a binary)", with_line=False)


def scan_blob(name, data, where, rep, stats, depth):
    ext = os.path.splitext(name)[1].lower()
    if ENV_NAME.match(name) and not ENV_TEMPLATE.search(name):
        rep.add("HIGH", "env-file-shipped", where, "An env file is inside what ships to users - everything in it is public")
    if ext == ".map":
        stats["maps"] += 1
        return
    if ext in SKIP_EXT:
        return
    if depth < 4 and is_archive(name):
        scan_archive(name, io.BytesIO(data), where, rep, stats, depth)
    elif b"\x00" in data[:8192]:
        scan_binary(data, where, rep)
    else:
        text = data.decode("utf-8", "ignore")
        scan_secrets(text, where, rep, note=SHIPPED)
        scan_config(text, where, name, rep)


def cmd_client(paths, rep):
    stats = {"maps": 0}
    for root in paths:
        if not os.path.exists(root):
            rep.add("INFO", "missing", root, "Path does not exist - nothing scanned")
            continue
        if os.path.isdir(os.path.join(root, ".git")):
            rep.add("HIGH", "git-dir-shipped", root, "A .git folder is inside the shipped output")
        for path in ([root] if os.path.isfile(root) else walk(root, skip_build=False)):
            name = os.path.basename(path)
            ext = os.path.splitext(name)[1].lower()
            try:
                if os.path.getsize(path) > MAX_BLOB:
                    rep.add("INFO", "too-large", path, "Skipped: larger than %d MB" % (MAX_BLOB // 2 ** 20))
                    continue
                with open(path, "rb") as f:
                    if is_archive(name):
                        scan_archive(name, f, path, rep, stats, 0)
                    else:  # media and .map files are only counted/flagged by name, never read
                        data = b"" if ext in SKIP_EXT or ext == ".map" else f.read()
                        scan_blob(name, data, path, rep, stats, 0)
            except OSError as e:
                rep.add("INFO", "unreadable", path, "Could not read: %s" % e)
    if stats["maps"]:
        rep.add("LOW", "source-maps", "%d .map files" % stats["maps"],
                "Source maps ship your original source code - fine if nothing in it is secret; consider disabling for production")


# ----------------------------------------------------------------------------- git history
def cmd_git(repo, rep):
    if run_git(repo, "rev-parse", "--is-inside-work-tree").strip() != "true":
        rep.add("INFO", "not-git", repo, "Not a git repository")
        return
    remotes = sorted({l.split()[1] for l in run_git(repo, "remote", "-v").splitlines() if len(l.split()) > 1})
    rep.add("INFO", "remotes", repo, "Remotes: %s - if any is public, everything in history is public" % (", ".join(remotes) or "none"))
    names = {n for n in run_git(repo, "log", "--all", "--pretty=format:", "--name-only").splitlines() if n}
    for n in sorted(names):
        base = os.path.basename(n)
        if ENV_NAME.match(base) and not ENV_TEMPLATE.search(base):
            added = run_git(repo, "log", "--all", "--diff-filter=A", "--format=%h %ad", "--date=short", "--", n).strip().splitlines()
            rep.add("HIGH", "env-in-history", n,
                    "Committed to git (first added %s). Every value it ever held counts as leaked if the repo was ever pushed "
                    "or shared - rotate them; deleting the file later does not remove it from history" % (added[-1] if added else "?"))
    proc = subprocess.Popen(["git", "-C", repo, "log", "--all", "-p", "--no-color", "--no-ext-diff", "--format=@@commit %h %ad",
                             "--date=short"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    commit = fname = "?"
    for raw in proc.stdout:
        line = raw.decode("utf-8", "ignore").rstrip("\n")
        if line.startswith("@@commit "):
            commit = line[9:]
        elif line.startswith("+++ "):
            fname = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("+"):
            sev_fn = (lambda s: "LOW") if TEST_PATH.search(fname) else (lambda s: s)
            scan_secrets(line[1:], "%s @ %s" % (fname, commit), rep, sev_fn, " - in git history", with_line=False,
                         dedupe_by_where=False)
    proc.wait()


# ----------------------------------------------------------------------------- live probe
PROBES = ["/.env", "/.env.local", "/.env.production", "/.env.backup", "/.git/config", "/.git/HEAD", "/.DS_Store", "/docs",
          "/redoc", "/openapi.json", "/actuator/env", "/debug/pprof/", "/plsc-404-check"]


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "pre-launch-security-check/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(262144)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(262144)
        except Exception:  # noqa: BLE001
            return e.code, b""
    except Exception as e:  # noqa: BLE001 - DNS, TLS, timeout: report as unreachable
        return None, str(e).encode()


def cmd_probe(urls, rep):
    for base in urls:
        base = base.rstrip("/")
        if not re.match(r"https?://", base):
            base = "https://" + base
        host = re.sub(r"^https?://", "", base).split("/")[0]
        if base.startswith("http://") and not re.match(r"(localhost|127\.|0\.0\.0\.0|\[::1\])", host):
            rep.add("MEDIUM", "plain-http", base, "Served over plain HTTP - tokens travel unencrypted; use HTTPS")
        st, body = fetch(base + "/")
        if st is None:
            rep.add("INFO", "unreachable", base, "Could not connect: " + body.decode("utf-8", "ignore")[:120])
            continue
        for p in PROBES:
            st, body = fetch(base + p)
            if st is None or not body:
                continue
            txt, url = body.decode("utf-8", "ignore"), base + p
            low = txt.lower()
            if p == "/plsc-404-check":  # what does an error page reveal?
                if "debug = true" in low and "django" in low:
                    rep.add("HIGH", "django-debug-live", url, "Django DEBUG mode is on in production (error pages show settings and code)")
                elif "werkzeug" in low and "debugger" in low:
                    rep.add("HIGH", "werkzeug-debugger-live", url, "Werkzeug interactive debugger is exposed - remote code execution")
                elif "rails.root" in low or "action controller: exception caught" in low:
                    rep.add("HIGH", "rails-dev-errors-live", url, "Rails development error pages are exposed")
                elif "traceback (most recent call last)" in low:
                    rep.add("MEDIUM", "traceback-live", url, "Error responses include Python tracebacks")
                continue
            if st != 200:
                continue
            if "<html" in low[:600] or "<!doctype" in low[:600]:
                if p in ("/docs", "/redoc") and ("swagger" in low or "redoc" in low):
                    rep.add("INFO", "api-docs-public", url, "Interactive API docs are public - fine if intended; otherwise disable "
                            "them in production (FastAPI: docs_url=None, redoc_url=None, openapi_url=None)")
                continue  # SPA fallback page, not the real file
            if p.startswith("/.env") and re.search(r"(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=", txt):
                tmp = Report()
                scan_secrets(txt, url, tmp, with_line=False)
                rep.add("HIGH", "env-served", url, "Env file is publicly downloadable (%d secret-looking values) - rotate "
                        "everything in it and stop serving it" % len(tmp.items))
            elif p.startswith("/.git") and ("[core]" in txt or txt.startswith("ref: ")):
                rep.add("HIGH", "git-served", url, "The .git folder is publicly downloadable - source and history can be rebuilt")
            elif p == "/.DS_Store" and body[:8] == b"\x00\x00\x00\x01Bud1":
                rep.add("LOW", "ds-store-served", url, "macOS .DS_Store is served - leaks file names")
            elif p == "/openapi.json" and '"openapi"' in txt[:300]:
                rep.add("INFO", "openapi-public", url, "OpenAPI schema is public - it lists every endpoint; fine if intended")
            elif p == "/actuator/env" and ('"propertysources"' in low or '"activeprofiles"' in low):
                rep.add("HIGH", "actuator-env-live", url, "Spring Boot /actuator/env is public - it shows configuration, often secrets")
            elif p == "/debug/pprof/" and "types of profiles available" in low:
                rep.add("MEDIUM", "pprof-live", url, "Go pprof debug endpoints are public")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["source", "client", "git", "probe"])
    ap.add_argument("targets", nargs="+")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args()
    rep = Report()
    if a.mode == "client":
        cmd_client(a.targets, rep)
    elif a.mode == "probe":
        cmd_probe(a.targets, rep)
    else:
        for t in a.targets:
            (cmd_source if a.mode == "source" else cmd_git)(t, rep)
    items = sorted(rep.items, key=lambda i: SEVS.index(i["severity"]))
    if a.json:
        print(json.dumps({"scan": a.mode, "targets": a.targets, "findings": items}, ensure_ascii=False, indent=1))
    else:
        print("== %s: %s ==" % (a.mode, " ".join(a.targets)))
        for i in items:
            print("[%s] %s  %s%s\n    %s" % (i["severity"], i["check"], i["where"],
                                            "  [%s]" % i["snippet"] if i["snippet"] else "", i["message"]))
        print("Summary: " + ", ".join("%d %s" % (sum(i["severity"] == s for i in items), s) for s in SEVS))
    sys.exit(1 if any(i["severity"] == "HIGH" for i in items) else 0)


if __name__ == "__main__":
    main()
