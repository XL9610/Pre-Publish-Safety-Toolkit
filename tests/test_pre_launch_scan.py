"""Tests for pre-launch-security-check/scripts/scan.py.

Every "secret" here is random fake data generated at runtime, so nothing real ever lands in the repo.
Run: python -m unittest discover -s tests -v
"""
import base64
import http.server
import io
import json
import os
import random
import shutil
import string
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile

SCAN = os.path.join(os.path.dirname(__file__), "..", "pre-launch-security-check", "scripts", "scan.py")
rng = random.Random(7)
ALNUM = string.ascii_letters + string.digits


def rnd(n, alphabet=ALNUM):
    while True:
        s = "".join(rng.choice(alphabet) for _ in range(n))
        if any(c.isdigit() for c in s) and any(c.isalpha() for c in s):
            return s


def jwt(role):
    def b(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return "%s.%s.%s" % (b({"alg": "HS256", "typ": "JWT"}), b({"iss": "supabase", "role": role}), rnd(43))


K = {
    "openai": "sk-proj-" + rnd(48),
    "old_openai": "sk-proj-" + rnd(48),
    "stripe": "sk_live_" + rnd(32),
    "resend": "re_" + rnd(8) + "_" + rnd(24),
    "anon": jwt("anon"),
    "service": jwt("service_role"),
    "sb_secret": "sb_secret_" + rnd(22) + "_" + rnd(8),
    "groq": "gsk_" + rnd(52),
    "xai": "xai-" + rnd(80),
    "hf": "hf_" + rnd(34),
    "aws": "AKIA" + rnd(16, string.ascii_uppercase + string.digits),
    "anthropic": "sk-ant-api03-" + rnd(80),
    "telegram": "%d:AA%s" % (rng.randint(10 ** 8, 10 ** 9 - 1), rnd(33)),
    "pk": "pk_live_" + rnd(32),
}


# Placeholder keys are assembled at runtime so secret scanners (GitHub push protection included) don't flag this file.
PH_STRIPE = "sk_" + "live_" + "x" * 24
PH_OPENAI = "sk-" + "proj-" + "x" * 24


def write(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(content, bytes) else "w") as f:
        f.write(content)
    return path


def git(root, *args):
    subprocess.run(["git", "-C", root] + list(args), check=True, capture_output=True)


def make_asar(files):
    """Build an Electron .asar archive in memory: [(path, bytes)]."""
    tree, blobs = {"files": {}}, b""
    for name, data in files:
        node = tree
        parts = name.split("/")
        for d in parts[:-1]:
            node = node["files"].setdefault(d, {"files": {}})
        node["files"][parts[-1]] = {"size": len(data), "offset": str(len(blobs))}
        blobs += data
    js = json.dumps(tree).encode()
    pad = (4 - len(js) % 4) % 4
    header = struct.pack("<II", 4 + len(js) + pad, len(js)) + js + b"\0" * pad
    return struct.pack("<II", 4, len(header)) + header + blobs


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            z.writestr(name, data)
    return buf.getvalue()


def make_tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def scan(mode, *targets):
    out = subprocess.run([sys.executable, SCAN, mode] + list(targets) + ["--json"], capture_output=True, text=True)
    assert out.returncode in (0, 1), out.stderr
    return json.loads(out.stdout)["findings"], out.returncode


class Findings:
    def __init__(self, items):
        self.items = items

    def find(self, check, where=None, sev=None):
        return [i for i in self.items if i["check"] == check and (where is None or where in i["where"])
                and (sev is None or i["severity"] == sev)]

    def nothing_in(self, where):
        return not [i for i in self.items if where in i["where"]]

    def leaked(self, value):
        return any(value in json.dumps(i) for i in self.items)


# ------------------------------------------------------------------------------------------- source
class SourceScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        r = cls.root
        git(r, "init", "-q")
        git(r, "config", "user.email", "t@example.invalid")
        git(r, "config", "user.name", "t")
        write(r, ".gitignore", "node_modules\ndist\n")  # .env deliberately NOT ignored
        write(r, ".env", "\n".join([
            "VITE_OPENAI_API_KEY=" + K["openai"],
            "NEXT_PUBLIC_STRIPE_SECRET=" + K["stripe"],
            "VITE_SUPABASE_ANON_KEY=" + K["anon"],
            "EXPO_PUBLIC_SUPABASE_KEY=" + K["service"],
            "VITE_ADMIN_TOKEN=hello-world",
            "VITE_STRIPE_PUBLISHABLE_KEY=" + K["pk"],
            "RESEND_API_KEY=" + K["resend"],
        ]) + "\n")
        write(r, ".env.example", "VITE_OPENAI_API_KEY=%s\nSTRIPE_SECRET_KEY=%s...\n" % (PH_OPENAI, PH_STRIPE[:8]))
        write(r, "vite.config.ts", "export default defineConfig({ define: { 'process.env': process.env } })\n")
        write(r, "src/api.ts", "export const GROQ = '%s'\n" % K["groq"])
        write(r, "src/style.css", ".sk-loading-spinner-container-wrapper { color: red }\n")
        write(r, "README.md", "Set your key, e.g. %s\n" % PH_STRIPE)
        write(r, "server/index.js", "app.use(cors())\napp.use(express.static(__dirname))\n")
        write(r, "django_app/settings.py", "DEBUG = True\nSECRET_KEY = 'django-insecure-abc123def456ghi'\n"
              "ALLOWED_HOSTS = ['*']\nCORS_ALLOW_ALL_ORIGINS = True\n")
        write(r, "flask_app/app.py", "CORS(app)\nif __name__ == '__main__':\n    app.run(host='0.0.0.0', debug=True)\n")
        write(r, "api/main.py", 'app = FastAPI(title="x", debug=True)\n'
              'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'
              'app.mount("/", StaticFiles(directory="."), name="root")\n'
              'LOCAL = "postgresql://postgres:postgres@localhost:5432/app"\n'
              'PROD = "postgresql://admin:%s@db.prod-host.net:5432/app"\n'
              'TEMPLATE = "postgres://${USER}:${PASS}@${HOST}/db"\n' % rnd(16))
        write(r, "firestore.rules", "service cloud.firestore {\n  match /databases/{db}/documents {\n"
              "    match /{doc=**} {\n      allow read, write: if request.time < timestamp.date(2026, 12, 1);\n    }\n  }\n}\n")
        write(r, "storage.rules", "service firebase.storage {\n  match /b/{bucket}/o {\n"
              "    match /{all=**} { allow read: if request.auth != null; }\n  }\n}\n")
        write(r, "database.rules.json", '{"rules": {".read": true, ".write": "auth != null"}}\n')
        write(r, "Dockerfile", "FROM python:3.12-slim\nENV OPENAI_API_KEY=abc\nCOPY . .\nCMD [\"python\", \"app.py\"]\n")
        write(r, "mobile/pubspec.yaml", "flutter:\n  assets:\n    - .env\n    - assets/images/\n")
        write(r, "mobile/package.json", '{"dependencies": {"react-native-config": "^1.5.0"}}\n')
        write(r, "electron/main.ts", "new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } })\n")
        write(r, "electron/preload.ts", "contextBridge.exposeInMainWorld('electron', { ipcRenderer })\n")
        write(r, "tests/test_keys.py", "FAKE = '%s'\n" % ("sk-proj-" + rnd(48)))
        write(r, "node_modules/lib/index.js", "const k = 'sk_test_%s'\n" % rnd(24))
        write(r, ".venv/pyvenv.cfg", "home = /usr/bin\n")
        write(r, ".venv/lib/x.py", "K = '%s'\n" % K["stripe"])
        write(r, "assets/logo.png", b"\x89PNG\r\n\x1a\n" + K["stripe"].encode())
        git(r, "add", "-A", ":!.env")
        git(r, "commit", "-qm", "app")
        f, cls.code = scan("source", r)
        cls.f = Findings(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_public_prefixed_secrets_are_high(self):
        for where in (".env:1", ".env:2", ".env:4"):
            self.assertTrue(self.f.find("public-prefixed-secret", where, "HIGH"), where)

    def test_public_by_design_keys_are_quiet(self):
        self.assertFalse(self.f.find("public-prefixed-secret", ".env:3"))  # Supabase anon
        self.assertFalse(self.f.find("public-prefixed-secret-name", ".env:6"))  # publishable
        self.assertFalse(self.f.find("public-prefixed-secret", ".env:7"))  # server-only var

    def test_secret_looking_name_is_medium(self):
        self.assertTrue(self.f.find("public-prefixed-secret-name", ".env:5", "MEDIUM"))

    def test_env_not_ignored(self):
        self.assertTrue(self.f.find("env-not-ignored", ".env", "HIGH"))

    def test_hardcoded_key_in_source(self):
        self.assertTrue(self.f.find("groq", "src/api.ts", "HIGH"))

    def test_build_config_and_web_servers(self):
        self.assertTrue(self.f.find("define-process-env", "vite.config.ts", "HIGH"))
        self.assertTrue(self.f.find("cors-any-js", "server/index.js"))
        self.assertTrue(self.f.find("static-root-js", "server/index.js", "HIGH"))

    def test_python_frameworks(self):
        for check in ("django-debug", "hardcoded-secret-key", "allowed-hosts-any", "cors-all-django"):
            self.assertTrue(self.f.find(check, "django_app/settings.py"), check)
        for check in ("cors-any-flask", "flask-debug"):
            self.assertTrue(self.f.find(check, "flask_app/app.py"), check)
        for check in ("fastapi-debug", "cors-wildcard-py", "static-root-py"):
            self.assertTrue(self.f.find(check, "api/main.py"), check)

    def test_db_urls(self):
        self.assertTrue(self.f.find("db-url", "api/main.py:5", "HIGH"))
        self.assertTrue(self.f.find("db-url", "api/main.py:4", "LOW"))
        self.assertFalse(self.f.find("db-url", "api/main.py:6"))  # ${...} template

    def test_firebase_rules(self):
        self.assertTrue(self.f.find("firebase-test-mode", "firestore.rules", "HIGH"))
        self.assertTrue(self.f.find("firebase-rtdb-open", "database.rules.json", "HIGH"))
        self.assertTrue(self.f.nothing_in("storage.rules"))

    def test_docker(self):
        self.assertTrue(self.f.find("docker-secret-env", "Dockerfile"))
        self.assertTrue(self.f.find("docker-context-env", "Dockerfile"))

    def test_mobile(self):
        self.assertTrue(self.f.find("flutter-env-asset", "mobile/pubspec.yaml", "HIGH"))
        self.assertTrue(self.f.find("rn-env-baked", "mobile/package.json"))

    def test_electron(self):
        self.assertTrue(self.f.find("electron-nodeIntegration", "electron/main.ts"))
        self.assertTrue(self.f.find("electron-contextIsolation-off", "electron/main.ts"))
        self.assertTrue(self.f.find("electron-expose-ipcRenderer", "electron/preload.ts"))

    def test_test_files_are_low(self):
        hits = [i for i in self.f.items if "tests/test_keys.py" in i["where"]]
        self.assertTrue(hits)
        self.assertTrue(all(i["severity"] == "LOW" for i in hits))

    def test_no_false_positives(self):
        for where in ("style.css", "README.md", "node_modules", ".venv", "logo.png"):
            self.assertTrue(self.f.nothing_in(where), where)
        self.assertFalse(self.f.find("secret-in-env-template"))
        self.assertFalse(self.f.find("jwt", ".env:3"))

    def test_never_prints_full_secrets(self):
        for name in ("openai", "stripe", "groq", "service", "resend"):
            self.assertFalse(self.f.leaked(K[name]), name)

    def test_exit_code(self):
        self.assertEqual(self.code, 1)


# ------------------------------------------------------------------------------------------- client
class ClientScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        r = cls.root
        write(r, "web/dist/assets/index.js", 'var e={a:"%s",b:"%s",c:"%s"};new BrowserWindow({webPreferences:'
              '{nodeIntegration:!0,contextIsolation:!1}});' % (K["openai"], K["anon"], K["pk"]))
        write(r, "web/dist/assets/index.js.map", '{"version":3}')
        write(r, "web/dist/.env", "RESEND_API_KEY=%s\n" % K["resend"])
        write(r, "web/dist/logo.png", b"\x89PNG" + K["stripe"].encode())
        asar = make_asar([
            ("package.json", b'{"name":"demo"}'),
            ("out/main/index.js", ('const s="%s";const svc="%s";' % (K["stripe"], K["service"])).encode()),
            (".env", ("SUPABASE_SECRET_KEY=%s\n" % K["sb_secret"]).encode()),
            ("node_modules/foo/index.js", ("const k='sk_test_%s'" % rnd(24)).encode()),
        ])
        write(r, "desktop/Demo.app/Contents/Resources/app.asar", asar)
        write(r, "desktop/Demo-mac.zip", make_zip([("Demo.app/Contents/Resources/app.asar", asar)]))
        dex = b"dex\n035\x00" + b"\x00" * 64 + K["telegram"].encode() + b"\x00" * 64
        write(r, "mobile/app-release.apk", make_zip([
            ("classes.dex", dex),
            ("assets/index.android.bundle", ("var x='%s';" % K["xai"]).encode()),
        ]))
        write(r, "pkg/lib-1.0.0.tgz", make_tgz([("package/dist/index.js", ("module.exports='%s'" % K["hf"]).encode())]))
        write(r, "pkg/tool-1.0-py3-none-any.whl", make_zip([("tool/config.py", ("AWS='%s'" % K["aws"]).encode())]))
        write(r, "native/myapp", b"\x7fELF\x02\x01\x01" + b"\x00" * 200 + K["anthropic"].encode() + b"\x00" * 200)
        write(r, "native/corrupt.apk", b"not really a zip " + K["stripe"].encode())
        f, cls.code = scan("client", os.path.join(r, "web/dist"), os.path.join(r, "desktop"), os.path.join(r, "mobile"),
                           os.path.join(r, "pkg"), os.path.join(r, "native"))
        cls.f = Findings(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_web_bundle(self):
        self.assertTrue(self.f.find("sk-dash", "index.js", "HIGH"))
        self.assertTrue(self.f.find("electron-nodeIntegration", "index.js"))
        self.assertTrue(self.f.find("env-file-shipped", "web/dist/.env", "HIGH"))
        self.assertTrue(self.f.find("source-maps"))

    def test_asar_and_nested_zip(self):
        self.assertTrue(self.f.find("sk-live", "Demo.app/Contents/Resources/app.asar!/out/main/index.js", "HIGH"))
        self.assertTrue(self.f.find("jwt", "app.asar!/out/main/index.js", "HIGH"))
        self.assertTrue(self.f.find("env-file-shipped", "app.asar!/.env"))
        self.assertTrue(self.f.find("sk-live", "Demo-mac.zip!/Demo.app/Contents/Resources/app.asar!/out/main/index.js"))

    def test_mobile_package(self):
        self.assertTrue(self.f.find("telegram-bot", "app-release.apk!/classes.dex", "HIGH"))
        self.assertTrue(self.f.find("xai", "app-release.apk!/assets/index.android.bundle", "HIGH"))

    def test_published_packages(self):
        self.assertTrue(self.f.find("huggingface", "lib-1.0.0.tgz!/package/dist/index.js"))
        self.assertTrue(self.f.find("aws-key-id", "tool-1.0-py3-none-any.whl!/tool/config.py"))

    def test_native_binary(self):
        self.assertTrue(self.f.find("anthropic", "native/myapp", "HIGH"))

    def test_corrupt_archive_falls_back(self):
        self.assertTrue(self.f.find("archive-unreadable", "corrupt.apk"))
        self.assertTrue(self.f.find("sk-live", "corrupt.apk"))

    def test_no_false_positives(self):
        self.assertTrue(self.f.nothing_in("node_modules"))
        self.assertTrue(self.f.nothing_in("logo.png"))
        self.assertFalse(any(i["check"] == "jwt" and "index.js" in i["where"] and "web/dist" in i["where"] for i in self.f.items))

    def test_never_prints_full_secrets(self):
        for v in K.values():
            self.assertFalse(self.f.leaked(v))


# ------------------------------------------------------------------------------------------- git
class GitScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        r = cls.root
        git(r, "init", "-q")
        git(r, "config", "user.email", "t@example.invalid")
        git(r, "config", "user.name", "t")
        write(r, ".env.production", "OPENAI_API_KEY=%s\n" % K["old_openai"])
        write(r, ".env.example", "OPENAI_API_KEY=\n")
        git(r, "add", "-A")
        git(r, "commit", "-qm", "oops")
        os.remove(os.path.join(r, ".env.production"))
        write(r, "app.py", "KEY = '%s'\n" % K["stripe"])
        git(r, "add", "-A")
        git(r, "commit", "-qm", "remove env, add app")
        f, _ = scan("git", r)
        cls.f = Findings(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_deleted_env_still_found(self):
        self.assertTrue(self.f.find("env-in-history", ".env.production", "HIGH"))
        self.assertTrue(self.f.find("sk-dash", ".env.production", "HIGH"))
        self.assertFalse(self.f.find("env-in-history", ".env.example"))

    def test_secret_in_code_history(self):
        self.assertTrue(self.f.find("sk-live", "app.py", "HIGH"))


# ------------------------------------------------------------------------------------------- probe
def serve(handler_fn):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status, ctype, body = handler_fn(self.path)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


class ProbeScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

        def leaky(path):
            if path == "/.env":
                return 200, "text/plain", ("OPENAI_API_KEY=%s\nDEBUG=1\n" % K["openai"]).encode()
            if path == "/.git/config":
                return 200, "text/plain", b"[core]\n\trepositoryformatversion = 0\n"
            if path == "/docs":
                return 200, "text/html", b"<!DOCTYPE html><html><title>Swagger UI</title></html>"
            if path == "/actuator/env":
                return 200, "application/json", b'{"activeProfiles":[],"propertySources":[]}'
            if path == "/plsc-404-check":
                return 404, "text/html", (b"<html>Page not found (404)... You're seeing this error because you have "
                                          b"<code>DEBUG = True</code> in your Django settings file.</html>")
            return 404, "text/plain", b"not found"

        def spa(path):
            return 200, "text/html", b"<!doctype html><html><body>app</body></html>"

        cls.servers = [serve(leaky), serve(spa)]
        f, _ = scan("probe", cls.servers[0][1], cls.servers[1][1])
        cls.f = Findings(f)
        cls.leaky_url, cls.spa_url = cls.servers[0][1], cls.servers[1][1]

    @classmethod
    def tearDownClass(cls):
        for srv, _ in cls.servers:
            srv.shutdown()

    def test_leaky_server(self):
        self.assertTrue(self.f.find("env-served", self.leaky_url, "HIGH"))
        self.assertTrue(self.f.find("git-served", self.leaky_url, "HIGH"))
        self.assertTrue(self.f.find("actuator-env-live", self.leaky_url, "HIGH"))
        self.assertTrue(self.f.find("django-debug-live", self.leaky_url, "HIGH"))
        self.assertTrue(self.f.find("api-docs-public", self.leaky_url))

    def test_spa_fallback_is_not_a_leak(self):
        self.assertTrue(self.f.nothing_in(self.spa_url))


if __name__ == "__main__":
    unittest.main()
