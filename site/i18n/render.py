#!/usr/bin/env python3
"""Render the product site in eight languages from site/index.html and tr/<lang>.txt.

    python3 render.py <repo> [lang ...]

Writes <repo>/site/index.html (English, with the language switcher and the IP-based
redirect) and <repo>/site/<lang>/index.html for every other language. Refuses to write
anything if a translation drops, adds or alters an HTML tag of its English segment.
"""
import html, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from seg import PAT, mask_pre  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LANGS = [  # code, native name, dir
    ("en", "English", "ltr"),
    ("zh", "中文", "ltr"),
    ("hi", "हिन्दी", "ltr"),
    ("es", "Español", "ltr"),
    ("ar", "العربية", "rtl"),
    ("fr", "Français", "ltr"),
    ("bn", "বাংলা", "ltr"),
    ("pt", "Português", "ltr"),
]
BASE = "https://skalenetwork.github.io/fermionwallet/"
ATTRS = {1: "content", 2: "content", 3: "content", 8: "alt", 9: "aria-label", 10: "alt", 11: "alt", 12: "alt", 13: "alt"}

# Country (ISO 3166-1 alpha-2) → page language. Anything else, or a failed lookup → English.
COUNTRY = {}
for cc in "CN TW HK MO SG".split():
    COUNTRY[cc] = "zh"
for cc in ["IN"]:
    COUNTRY[cc] = "hi"
for cc in ["BD"]:
    COUNTRY[cc] = "bn"
for cc in "ES MX AR CO CL PE VE EC GT CU BO DO HN PY SV NI CR PA UY PR GQ".split():
    COUNTRY[cc] = "es"
for cc in "BR PT AO MZ CV GW ST TL".split():
    COUNTRY[cc] = "pt"
for cc in "FR BE LU MC CD CI CM SN ML BF NE TG BJ GA CG MG HT GN TD CF BI RW DJ KM".split():
    COUNTRY[cc] = "fr"
for cc in "SA AE EG IQ JO KW LB LY MA DZ TN OM QA BH SY YE SD PS MR".split():
    COUNTRY[cc] = "ar"

TAG = re.compile(r"<[^>]+>")


def load_tr(path):
    text = open(path, encoding="utf-8").read()
    parts = re.split(r"^@@ (A?\d+)( =)?[ \t]*\n?", text, flags=re.M)
    out = {}
    for i in range(1, len(parts), 3):
        key, same, body = parts[i], parts[i + 1], parts[i + 2]
        out[key] = None if same else body.rstrip("\n")
    return out


def tags(s):
    return sorted(TAG.findall(s))


def switcher(lang, prefix):
    opts = []
    for code, name, _ in LANGS:
        sel = " selected" if code == lang else ""
        opts.append(f'<option value="{code}"{sel}>{name}</option>')
    return (
        f'<select class="lang-switch" aria-label="Language" data-prefix="{prefix}" '
        f'onchange="fermionSetLang(this.value)">' + "".join(opts) + "</select>"
    )


SWITCH_CSS = """
.lang-switch { font: inherit; font-size: 14px; color: var(--text); background: var(--bg-card);
  border: 1px solid var(--border); border-radius: 8px; padding: 6px 8px; cursor: pointer; }
@media (max-width: 600px) { .lang-switch { max-width: 84px; padding: 6px 4px; font-size: 13px; } }
html[dir="rtl"] .code, html[dir="rtl"] pre, html[dir="rtl"] code { direction: ltr; unicode-bidi: isolate; }
"""

SWITCH_JS = """<script>
function fermionSetLang(l) {
  try { localStorage.setItem('fermion-lang', l); } catch (e) {}
  var p = document.querySelector('.lang-switch').getAttribute('data-prefix');
  location.href = p + (l === 'en' ? '' : l + '/') + location.hash;
}
</script>"""


def detect_js():
    return """<script>
/* Language by visitor IP: on the English root page only, look the visitor's country up once
   (api.country.is, no key, no cookies) and move to that country's language. A choice made
   with the switcher always wins. Any failure, timeout or unmapped country: stay in English. */
(function () {
  var L = %s, C = %s, saved = null;
  function go(l) { if (l && l !== 'en' && L.indexOf(l) > 0) location.replace(l + '/' + location.hash); }
  try { saved = localStorage.getItem('fermion-lang'); } catch (e) {}
  if (saved) { go(saved); return; }
  if (!window.fetch) return;
  var ctl = window.AbortController ? new AbortController() : null;
  var timer = setTimeout(function () { if (ctl) ctl.abort(); }, 1500);
  fetch('https://api.country.is/', { cache: 'no-store', signal: ctl ? ctl.signal : undefined })
    .then(function (r) { return r.json(); })
    .then(function (j) { clearTimeout(timer); go(C[String(j.country || '').toUpperCase()]); })
    .catch(function () {});
})();
</script>""" % (json.dumps([c for c, _, _ in LANGS]), json.dumps(COUNTRY, sort_keys=True))


def render(src, lang, tr):
    code, name, direction = next(x for x in LANGS if x[0] == lang)
    sub = lang != "en"
    prefix = "../" if sub else ""
    out = src
    b = out.index("<body")
    head, body = out[:b], out[b:]

    if sub:
        segs = json.load(open(os.path.join(HERE, "segs.json"), encoding="utf-8"))
        table = {}
        for i, en in enumerate(segs):
            t = tr.get(str(i), "MISSING")
            if t == "MISSING":
                raise SystemExit(f"{lang}: segment {i} missing")
            if t is None:
                t = en
            if tags(t) != tags(en):
                raise SystemExit(f"{lang}: segment {i} changes the HTML tags\n  en: {tags(en)}\n  {lang}: {tags(t)}")
            table[en] = t
        masked, pres = mask_pre(body)

        def rep(m):
            inner = m.group(3)
            key = inner.strip()
            if key not in table:
                return m.group(0)
            lead = inner[: len(inner) - len(inner.lstrip())]
            trail = inner[len(inner.rstrip()):]
            return f"<{m.group(1)}{m.group(2)}>{lead}{table[key]}{trail}</{m.group(1)}>"

        masked = PAT.sub(rep, masked)
        for i, p in enumerate(pres):
            masked = masked.replace(f"\x00PRE{i}\x00", p)
        body = masked
        strings = json.load(open(os.path.join(HERE, "strings.json"), encoding="utf-8"))["attrs"]
        for idx, attr in ATTRS.items():
            en = strings[idx][2]
            t = tr.get(f"A{idx}")
            if not t:
                raise SystemExit(f"{lang}: attribute A{idx} missing")
            for part in ("head", "body"):
                s = head if part == "head" else body
                needle = f'{attr}="{html.escape(en, quote=True)}"'
                if needle not in s:
                    needle = f'{attr}="{en}"'
                s = s.replace(needle, f'{attr}="{html.escape(t, quote=True)}"')
                if part == "head":
                    head = s
                else:
                    body = s
        body = body.replace('src="assets/', 'src="../assets/').replace('href="assets/', 'href="../assets/')
        head = head.replace('href="assets/', 'href="../assets/')
        head = head.replace(f'content="{BASE}"', f'content="{BASE}{lang}/"')

    head = head.replace('<html lang="en">', f'<html lang="{code}" dir="{direction}">', 1)
    alts = "".join(
        f'<link rel="alternate" hreflang="{c}" href="{BASE}{"" if c == "en" else c + "/"}">\n' for c, _, _ in LANGS
    ) + f'<link rel="alternate" hreflang="x-default" href="{BASE}">\n'
    head = head.replace("</style>", SWITCH_CSS + "</style>", 1)
    head = head.replace("</head>", alts + SWITCH_JS + "\n" + ("" if sub else detect_js() + "\n") + "</head>", 1)
    body = body.replace(
        '<a class="hide-sm" href="https://github.com/skalenetwork/fermionwallet">GitHub</a>',
        '<a class="hide-sm" href="https://github.com/skalenetwork/fermionwallet">GitHub</a>\n      ' + switcher(lang, prefix),
        1,
    )
    if switcher(lang, prefix) not in body:
        raise SystemExit(f"{lang}: could not place the language switcher")
    return head + body


def main():
    repo = sys.argv[1]
    only = sys.argv[2:]
    src_path = os.path.join(repo, "site", "index.html")
    src = open(os.path.join(HERE, "index.en.html"), encoding="utf-8").read()
    outputs = {}
    for code, _, _ in LANGS:
        if only and code not in only and code != "en":
            continue
        tr = {} if code == "en" else load_tr(os.path.join(HERE, "tr", f"{code}.txt"))
        outputs[code] = render(src, code, tr)
    for code, page in outputs.items():
        path = src_path if code == "en" else os.path.join(repo, "site", code, "index.html")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w", encoding="utf-8").write(page)
        print(f"wrote {path} ({len(page)} bytes)")


if __name__ == "__main__":
    main()
