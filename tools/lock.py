#!/usr/bin/env python3
"""Password-lock a static page for GitHub Pages.

The page's <body> is encrypted (AES-256-GCM, key from PBKDF2-SHA256), so the
public file holds only a welcome/login modal plus ciphertext. Nothing private
is readable in the source without the password. The browser decrypts it with
the built-in Web Crypto API; no server needed.

Usage
  lock:    python3 tools/lock.py lock   welcome/index.plain.html welcome/index.html
  unlock:  python3 tools/lock.py unlock welcome/index.html welcome/index.plain.html

The password is read from $PAGE_PASSWORD, or asked for if that isn't set.
*.plain.html files are git-ignored: never commit the readable copy.
"""
import base64, getpass, json, os, re, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 250_000
START, END = "<!--lock:start-->", "<!--lock:end-->"
BODY_RE = re.compile(r"(<body[^>]*>)(.*)(</body>)", re.S)

LOCK_HEAD = START + r"""
<meta name="robots" content="noindex, nofollow">
<style>
/* Login modal: club-maroon backdrop, one card, password only. */
html.locked body { overflow: hidden; }
.gate {
  position: fixed; inset: 0; z-index: 50; overflow-y: auto;
  background: radial-gradient(120% 90% at 85% 0%, var(--maroon) 0%, var(--maroon-deep) 55%, var(--navy) 130%);
  display: grid; place-items: center; grid-template-columns: minmax(0, 1fr);
  padding: max(24px, env(safe-area-inset-top, 0px)) max(16px, env(safe-area-inset-right, 0px)) max(24px, env(safe-area-inset-bottom, 0px)) max(16px, env(safe-area-inset-left, 0px));
}
html.checking .gate-card { opacity: 0; }
.gate-card {
  width: 100%; max-width: 440px; background: var(--surface); color: var(--ink);
  border-radius: 10px; box-shadow: 0 24px 60px rgba(0,0,0,.35);
  overflow: hidden; transition: opacity .2s;
}
.gate-top { background: var(--maroon); color: var(--on-accent); padding: 26px 26px 22px; display: grid; gap: 10px; justify-items: start; }
.gate-crest { width: 72px; height: 72px; object-fit: contain; }
.gate-top .eyebrow { font-size: 12px; }
.gate-top h1 { font-size: 40px; line-height: 1; text-transform: uppercase; font-weight: 600; letter-spacing: .01em; }
.gate-top p { margin: 0; font-size: 16px; }
.gate-form { padding: 22px 26px 26px; display: grid; gap: 12px; grid-template-columns: minmax(0, 1fr); }
.gate-form label { font-family: var(--font-display); text-transform: uppercase; letter-spacing: .08em; font-size: 14px; color: var(--accent-text); }
.gate-field { display: flex; border: 2px solid var(--line); border-radius: 6px; background: var(--bg); }
.gate-field:focus-within { border-color: var(--maroon); }
.gate-field input { flex: 1; min-width: 0; border: 0; background: transparent; color: var(--ink); font: 18px var(--font-body); padding: 12px 14px; outline: none; }
.gate-field button { border: 0; background: transparent; color: var(--muted); font: 500 12px var(--font-body); text-transform: uppercase; letter-spacing: .06em; padding: 0 14px; cursor: pointer; }
.gate-hint { margin: 0; font-size: 14px; color: var(--muted); }
.gate-form .gate-remember { font-family: var(--font-body); text-transform: none; letter-spacing: 0; display: flex; gap: 8px; align-items: center; font-size: 14px; color: var(--muted); }
.gate-form .gate-remember input { accent-color: var(--maroon); width: 16px; height: 16px; }
.gate-go { border: 0; cursor: pointer; font-size: 17px; padding: 13px 16px; text-align: center; }
.gate-go[disabled] { opacity: .7; cursor: progress; }
.gate-error:empty { display: none; }
.gate-error { margin: 0; min-height: 1.4em; font-size: 14px; color: #B3261E; }
:root[data-theme="dark"] .gate-error { color: #F2B8B5; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) .gate-error { color: #F2B8B5; } }
.gate-sign { margin: 4px 0 0; font-family: var(--font-display); font-size: 17px; color: var(--ink); }
.shake { animation: shake .4s; }
@keyframes shake { 20%, 60% { transform: translateX(-6px); } 40%, 80% { transform: translateX(6px); } }
</style>
<script>document.documentElement.classList.add('locked', 'checking');</script>
""" + END

LOCK_BODY = r"""
<div class="gate" role="dialog" aria-modal="true" aria-labelledby="gate-h" aria-describedby="gate-intro">
  <div class="gate-card">
    <div class="gate-top">
      <img class="gate-crest" src="https://prodcdn.sporty.co.nz/cms/13818/83131/1442870/bf252aa4-da9f-4931-8a67-9d34d3b929ef_wo.png?t=638882118001570000" alt="Eastern Suburbs Cricket Club logo" width="72" height="72" onerror="this.remove()">
      <div class="eyebrow">Eastern Suburbs Junior Cricket Club · Summer 2026/27</div>
      <h1 id="gate-h">Kia ora, Gladiators!</h1>
      <p id="gate-intro">Welcome to our team guide for the season: who's who, when we play, and how you can help. It's just for our players and whānau, so it sits behind a team password.</p>
    </div>
    <form class="gate-form" id="gate-form" autocomplete="off">
      <label for="gate-pw">Team password</label>
      <div class="gate-field">
        <input id="gate-pw" type="password" required autocapitalize="off" autocorrect="off" spellcheck="false" aria-describedby="gate-hint gate-error">
        <button type="button" id="gate-peek" aria-pressed="false" aria-label="Show password">Show</button>
      </div>
      <p class="gate-hint" id="gate-hint">You'll find it in the description of our team WhatsApp group.</p>
      <label class="gate-remember"><input type="checkbox" id="gate-remember" checked> Remember me on this device</label>
      <button class="btn gate-go" id="gate-go" type="submit">Walk out to bat</button>
      <p class="gate-error" id="gate-error" role="alert"></p>
      <p class="gate-sign">Ngā mihi, Ants &amp; Simon</p>
    </form>
  </div>
</div>
<script type="application/json" id="locked-data">__PAYLOAD__</script>
<script>
(function () {
  var P = JSON.parse(document.getElementById('locked-data').textContent);
  var STORE = 'gladiators-welcome:' + P.salt.slice(0, 12);
  var root = document.documentElement;
  var form = document.getElementById('gate-form'), pw = document.getElementById('gate-pw');
  var go = document.getElementById('gate-go'), err = document.getElementById('gate-error');
  var remember = document.getElementById('gate-remember'), peek = document.getElementById('gate-peek');

  function fromB64(s) { var b = atob(s), u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function toB64(buf) { var u = new Uint8Array(buf), s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
  function store(fn) { try { return fn(window.localStorage); } catch (e) { return null; } }

  function derive(password) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) {
        return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: fromB64(P.salt), iterations: P.iter, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
      });
  }
  function decrypt(key) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(P.iv) }, key, fromB64(P.ct))
      .then(function (buf) { return new TextDecoder().decode(buf); });
  }
  function reveal(html) {
    document.body.innerHTML = html;
    // Scripts added via innerHTML don't run, so re-create them.
    document.body.querySelectorAll('script').forEach(function (old) {
      var s = document.createElement('script'); s.textContent = old.textContent; old.replaceWith(s);
    });
    root.classList.remove('locked', 'checking');
    var id = location.hash.slice(1), t = id && document.getElementById(id);
    if (t) t.scrollIntoView();
  }
  function ready() { root.classList.remove('checking'); pw.focus(); }

  if (!window.crypto || !crypto.subtle) {
    ready(); err.textContent = 'This browser can’t open the guide. Try an up-to-date Safari, Chrome or Firefox.';
    go.disabled = true; return;
  }

  // Returning visitor: try the remembered key first.
  var saved = store(function (s) { return s.getItem(STORE); });
  if (saved) {
    crypto.subtle.importKey('raw', fromB64(saved), 'AES-GCM', false, ['decrypt'])
      .then(decrypt).then(reveal)
      .catch(function () { store(function (s) { s.removeItem(STORE); }); ready(); });
  } else { ready(); }

  peek.addEventListener('click', function () {
    var show = pw.type === 'password';
    pw.type = show ? 'text' : 'password';
    peek.textContent = show ? 'Hide' : 'Show';
    peek.setAttribute('aria-pressed', String(show));
    peek.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    pw.focus();
  });

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (!pw.value) return;
    go.disabled = true; go.textContent = 'Padding up…'; err.textContent = '';
    var key;
    derive(pw.value)
      .then(function (k) { key = k; return decrypt(k); })
      .then(function (html) {
        if (remember.checked) {
          return crypto.subtle.exportKey('raw', key).then(function (raw) {
            store(function (s) { s.setItem(STORE, toB64(raw)); });
            reveal(html);
          });
        }
        reveal(html);
      })
      .catch(function () {
        go.disabled = false; go.textContent = 'Walk out to bat';
        err.textContent = 'Not quite: that one’s gone through to the keeper. Check the WhatsApp group description and try again.';
        var card = document.querySelector('.gate-card');
        card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
        pw.select();
      });
  });
})();
</script>
"""


def password():
    return os.environ.get("PAGE_PASSWORD") or getpass.getpass("Page password: ")


def derive(pw, salt, iterations):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive(pw.encode("utf-8"))


def lock(src, dst):
    html = open(src, encoding="utf-8").read()
    if START in html:
        sys.exit("Source already looks locked. Pass the readable (.plain.html) copy.")
    m = BODY_RE.search(html)
    if not m:
        sys.exit("No <body> found.")
    salt, iv = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive(password(), salt, ITERATIONS)).encrypt(iv, m.group(2).encode("utf-8"), None)
    b64 = lambda b: base64.b64encode(b).decode()
    payload = json.dumps({"v": 1, "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)})
    out = html[: m.start()] + m.group(1) + LOCK_BODY.replace("__PAYLOAD__", payload) + m.group(3) + html[m.end():]
    out = out.replace("</head>", LOCK_HEAD + "\n</head>", 1)
    open(dst, "w", encoding="utf-8").write(out)
    print(f"Locked {src} -> {dst}")


def unlock(src, dst):
    html = open(src, encoding="utf-8").read()
    p = json.loads(re.search(r'<script type="application/json" id="locked-data">(.*?)</script>', html, re.S).group(1))
    d = lambda s: base64.b64decode(s)
    try:
        body = AESGCM(derive(password(), d(p["salt"]), p["iter"])).decrypt(d(p["iv"]), d(p["ct"]), None).decode("utf-8")
    except Exception:
        sys.exit("Wrong password.")
    html = re.sub(re.escape(START) + ".*?" + re.escape(END) + r"\n?", "", html, flags=re.S)
    m = BODY_RE.search(html)
    open(dst, "w", encoding="utf-8").write(html[: m.start()] + m.group(1) + body + m.group(3) + html[m.end():])
    print(f"Unlocked {src} -> {dst}")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("lock", "unlock"):
        sys.exit(__doc__)
    {"lock": lock, "unlock": unlock}[sys.argv[1]](sys.argv[2], sys.argv[3])
