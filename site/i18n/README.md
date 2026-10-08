# Product site translations

The product site is published in eight languages: English at `/`, and Chinese (`zh`), Hindi
(`hi`), Spanish (`es`), Arabic (`ar`, right to left), French (`fr`), Bengali (`bn`) and
Portuguese (`pt`) at `/<lang>/`.

**Language choice.** The English root page looks up the visitor's country from their IP
address once (`https://api.country.is/`: no key, no cookies) and moves to that country's
language. If the lookup fails, times out (1.5 s) or the country isn't mapped, the page stays
in English. A choice made with the language switcher in the navigation bar is remembered in
`localStorage` and always wins. Pages other than the root never redirect. The
country-to-language map is `COUNTRY` in `render.py`.

**Editing the site.** `index.en.html` here is the English source. Do not edit
`site/index.html` or `site/<lang>/index.html` by hand; they are generated.

1. Edit `index.en.html`.
2. `python3 site/i18n/seg.py site/i18n/index.en.html site/i18n/segs.json` re-extracts the
   translatable blocks. A changed block gets a new index, so check `segs.json`.
3. Update `tr/<lang>.txt` for every changed block. Each block is `@@ <index>` followed by its
   translation (`@@ <index> =` keeps the English), and `@@ A<n>` holds attribute text
   (`<meta>` descriptions, image `alt`, `aria-label`). A translation must keep exactly the
   HTML tags of its English block, so links, `<code>` and emphasis survive translation;
   `render.py` refuses to write anything otherwise.
4. `python3 site/i18n/render.py .` from the repository root regenerates all eight pages.
