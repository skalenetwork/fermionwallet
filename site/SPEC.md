# FermionWallet Product Site Specification

Specification for the public product site at **https://skalenetwork.github.io/fermionwallet/**. It defines who the site is for, what it must make visitors do, what it may and may not claim, its structure, design rules, build and deployment, and the checks every change must pass.

The implementation is [`site/index.html`](./index.html). If the implementation and this spec disagree, fix one of them in the same change.

## 1. Purpose

The site turns a visitor who holds, or advises on, assets in a Gnosis Safe into an **early-access request**. Everything on the page serves that, or serves the trust needed for it.

The site is not documentation. It links to the specs in this repository for depth and never duplicates them.

## 2. Audiences

| Audience | What they need to see | Where on the page |
|---|---|---|
| Treasury, custody and risk leads (decision makers) | The outcome, that nothing is migrated, what it costs their team, and whether it's trustworthy | Hero, setup, who it's for, security, FAQ |
| Safe owners and operators | How their daily flow changes | How it works, setup |
| Engineers and auditors (evaluators) | That the cryptography is real and verifiable | "For your engineers" section, links to contracts and specs |
| Investors and partners | Credibility of the team and the approach | Author section, status |

Decision makers are the primary audience. The page must work for someone who reads only the hero, the setup section and the FAQ.

## 3. Conversion goals

| Priority | Action | Mechanism |
|---|---|---|
| Primary | Request early access | "Get early access" / "Request early access" buttons |
| Secondary | Understand the product | "See how it works" |
| Tertiary | Follow the project | "Star on GitHub" |

Rules:

- The primary action appears in the sticky navigation (visible on every scroll position and on phones), in the hero, and in the final section.
- Primary and secondary buttons are visually distinct: filled accent versus outlined.
- The early-access request currently opens a pre-filled **public** GitHub issue. The page states that it's public next to the final button. Replacing it with a private channel (email or form) is an open decision (§10).

## 4. Content rules

These rules exist because a product site for a security product loses all credibility with a single false claim.

1. **Every factual claim must be traceable to the repository.** Numbers, standards, timelocks, supported versions and features come from the spec documents or measured results, never from assumption.
2. **Status is stated honestly.** The status section says what is implemented, designed and in development, and the footer says the product is not yet audited. Neither may be removed until the facts change.
3. **No invented social proof.** No customer logos, testimonials, user counts or partner names unless they exist and permission is on record.
4. **No availability promises.** No dates, pricing or guarantees that aren't decided.
5. **Plain language first.** Above the "For your engineers" section, avoid unexplained jargon (EIP-712, WOTS+, leaf, bitmap). Technical terms go in the engineers section and the linked specs.
6. **Simplified code is labelled.** Any code excerpt that differs from the source file carries "(simplified)" in its title.

### 4.1 Claims register

Each claim on the page and its source. Update this table when a claim is added or changed.

| Claim on page | Source |
|---|---|
| Installs as a Safe Guard; owners, threshold and history unchanged | [ui-help.md](../ui-help.md#adding-the-guard-to-an-existing-safe) |
| Four setup steps, about 30 minutes | [ui-help.md](../ui-help.md#adding-the-guard-to-an-existing-safe) |
| XMSS, RFC 8391, NIST SP 800-208 | [fermionwallet-guard-module.md](../fermionwallet-guard-module.md) |
| 999,247 gas per verification at h = 20 | [contracts/README.md](../contracts/README.md#measured-gas) |
| About 1M approvals per key (2^20 leaves) | [fermionwallet-guard-module.md](../fermionwallet-guard-module.md) |
| Tested at h = 4, 10, 20 against an independent reference | [contracts/README.md](../contracts/README.md) |
| 48-hour admin timelock; any single owner can revoke | [ui-help.md](../ui-help.md#administrative-approvals-and-the-timelock) |
| 14-day owners-only emergency removal; Administrator can cancel | [ui-help.md](../ui-help.md#emergency-guard-removal-owners-only) |
| One approval per batch of up to 100 transfers | [ui-help.md](../ui-help.md#approving-a-batch-multisend) |
| `approve`, `permit`, `transferFrom` rejected | [fermionwallet-guard-module.md](../fermionwallet-guard-module.md) |
| Safe v1.3.0+; no modules, or module guard on 1.5+ | [ui-help.md](../ui-help.md#adding-the-guard-to-an-existing-safe) |
| Lattice schemes cost tens of millions of gas on-chain | [fermionwallet-guard-module.md](../fermionwallet-guard-module.md) |
| Exportable audit log; printable ceremony record | [ui-help.md](../ui-help.md#audit-log-and-export) |
| Author credentials | [readme.md](../readme.md) |
| Status of each component | [release-spec.md §11](../release-spec.md#11-current-readiness) |

The 48-hour and 14-day values are the user guide's defaults; the release spec lists the final values as an open decision. If they change, update the page.

## 5. Page structure

Sections appear in this order. Each has one job.

| # | Section | Anchor | Job |
|---|---|---|---|
| 1 | Navigation (sticky) | — | Wayfinding; always-visible primary CTA |
| 2 | Hero | `#top` | State audience, outcome and main objection-killers; primary + secondary CTA; product screenshot |
| 3 | Trust bar | — | Standards and building blocks at a glance |
| 4 | Why now | — | Explain why a multisig alone isn't enough |
| 5 | How it works | `#how` | Two signatures, the five-step flow, approval and Ledger screens |
| 6 | Setup | — | Remove the migration objection: four steps, ~30 minutes |
| 7 | Who it's for | — | Let each segment recognise itself |
| 8 | Security | `#security` | Show it can't be bypassed and can't lock funds |
| 9 | For your engineers | — | Evidence for evaluators: gas, tests, code |
| 10 | Status | `#status` | Honest readiness |
| 11 | Author | — | Team credibility |
| 12 | FAQ | `#faq` | Answer objections that block a request |
| 13 | Early access | `#early-access` | Final CTA and what happens after requesting |
| 14 | Footer | — | Links to docs, reference, security; audit disclaimer |

### 5.1 Hero requirements

- Audience tag, headline, one-sentence subheading, two buttons, three reassurance points, one product screenshot.
- The headline names the outcome ("quantum-safe second signature") and the product it attaches to (Safe).
- The reassurance points must remain true: no migration, open source (MIT), NIST SP 800-208 signatures.

### 5.2 FAQ requirements

The FAQ must answer at least: whether assets move; what happens if the Ledger is lost; operational slowdown; gas cost; supported Safe versions; why XMSS; production readiness. Answers are two to three sentences and follow the claims register.

## 6. Design

### 6.1 Visual language

- Style reference: react.dev — generous whitespace, large bold headings, centred section intros, cards, rounded buttons.
- Typefaces: Inter (text), JetBrains Mono (code), loaded from Google Fonts with system fallbacks.
- One accent color. All colors are CSS custom properties on `:root`.

### 6.2 Themes

- Light and dark follow `prefers-color-scheme`, and can be forced with `data-theme="light"` or `data-theme="dark"` on `<html>`.
- Every color used must be defined for both themes, including text on accent buttons.

### 6.3 Layout

- Content max width 1180px; side gutter 16px on phones, 32px from 720px.
- No horizontal scrolling at any width down to 320px. Code blocks scroll inside their box.
- Multi-column grids collapse to one column on phones. Image-and-text splits stack with the image first.
- The navigation hides secondary links below 860px but always keeps the primary CTA.

### 6.4 Images

- Product screenshots come from `assets/ui/` and must match the current design of the Safe App and Ledger app.
- Every image has descriptive `alt` text; decorative images use `alt=""`.

## 7. Technical requirements

- A single static HTML file with inline CSS. No JavaScript, no build step, no framework.
- External requests are limited to Google Fonts. No third-party scripts or trackers without an explicit decision (§10).
- Asset paths are relative (`assets/...`) so the site works under the `/fermionwallet/` path.
- Metadata: `<title>`, meta description, Open Graph title, description, URL and image, and a favicon.
- Anchors used by navigation (`#how`, `#security`, `#faq`, `#early-access`) must exist. `scroll-padding-top` keeps anchored headings clear of the sticky nav.
- Links to documentation point at `https://github.com/skalenetwork/fermionwallet/blob/main/<file>`.

### 7.1 Accessibility

- Semantic landmarks: `nav`, `header`, `section`, `footer`; one `h1`.
- FAQ uses native `<details>`/`<summary>` so it works with keyboard and screen readers without script.
- Text contrast meets WCAG 2.1 AA in both themes.
- Status and meaning are never carried by color or emoji alone.

## 8. Build and deployment

- Source: `site/index.html` plus `assets/fermionwallet-logo.svg` and `assets/ui/`.
- Workflow: [`.github/workflows/pages.yml`](../.github/workflows/pages.yml) assembles `_site/` (page, logo, UI mockups, `.nojekyll`) and deploys with `actions/upload-pages-artifact` and `actions/deploy-pages`.
- Triggers: manual (`workflow_dispatch`) and any push to `main` that changes `site/**`, `assets/**` or the workflow itself.
- Repository setting: **Settings → Pages → Source: GitHub Actions**.
- A deployment is complete when the live URL serves the new version (for example, grep the new headline).

## 9. Change checklist

Every change to the site must pass these before merge:

- [ ] Every new or changed claim is in the claims register (§4.1) with a source.
- [ ] Status section and audit disclaimer still match [release-spec.md §11](../release-spec.md#11-current-readiness).
- [ ] Rendered and checked at 1280px and 390px wide, in light and dark themes; no horizontal scroll.
- [ ] All `assets/...` paths exist in `_site/` as assembled by the workflow.
- [ ] All links resolve; navigation anchors exist.
- [ ] Primary CTA visible in nav, hero and final section.
- [ ] After merge: live URL serves the change.

## 10. Open decisions

| # | Decision | Current state |
|---|---|---|
| S1 | Early-access channel | Public, pre-filled GitHub issue. A private email or form would suit institutional visitors better |
| S2 | Analytics | None. Needed to measure conversion; a privacy-friendly tool (for example Plausible) is the least invasive option |
| S3 | Custom domain | Served from `skalenetwork.github.io`. The deployment spec names `app.fermionwallet.io` for the Safe App; a matching product domain is undecided |
| S4 | Social preview image | Open Graph image is an SVG, which many platforms don't render. A 1200×630 PNG is needed |
| S5 | Theme toggle | Theme follows the operating system only; no visible switch |

## 11. Success measures

Once analytics exist (S2):

- Early-access requests per week.
- Click-through rate of the primary CTA from the hero and from the final section.
- Share of visitors reaching the FAQ and the early-access section.
- Clicks into the spec and contracts links (evaluator interest).
