---
name: engagement-retention
version: 1.0.0
description: >
  Domain sub-skill that audits above-the-fold navigation and H1 orientation,
  detects post-load interstitials and modals that degrade AI-readable content,
  and measures viewport layout stability (CLS proxy).
entrypoint: false
tags:
  - UX
  - engagement
  - interstitial
  - CLS
  - above-the-fold
  - navigation
author: brand-ai-readiness-audit contributors
license: MIT
python_requires: ">=3.10"
dependencies:
  - requests>=2.31.0
  - beautifulsoup4>=4.12.0
  - lxml>=5.0.0
  - playwright>=1.43.0
allowed-tools: Read
---

# Engagement & Retention

## Purpose

AI engines consider user-experience signals when evaluating content quality.
This skill audits three pillars:

1. **Above-the-Fold Orientation** — Verify that the primary `<h1>`, primary
   navigation, and a clear brand signal appear within the initial viewport
   without scrolling, using both static HTML analysis and optional Playwright.
2. **Post-Load Interstitial Detection** — Detect full-page overlays, cookie
   consent banners, newsletter modals, and GDPR notices that cover a
   significant portion of the viewport after page load, potentially obscuring
   main content from crawlers.
3. **Viewport Stability** — Heuristically proxy Cumulative Layout Shift (CLS)
   by detecting dynamically injected elements with absolute/fixed positioning
   that appear after initial render.

## Checks & Finding IDs

| Finding ID                         | Severity | Trigger Condition                                |
|------------------------------------|----------|--------------------------------------------------|
| `missing-h1-above-fold`            | high     | No `<h1>` in the first viewport                  |
| `missing-nav-above-fold`           | medium   | No `<nav>` or equivalent above the fold          |
| `interstitial-full-page-overlay`   | high     | Fixed/absolute element covers >60% of viewport  |
| `interstitial-cookie-banner`       | medium   | Cookie consent element detected post-load        |
| `interstitial-newsletter-modal`    | low      | Newsletter/subscribe modal detected post-load    |
| `viewport-late-injected-fixed`     | medium   | Fixed-position element injected after load       |
| `multiple-h1-tags`                 | low      | More than one `<h1>` on a single page            |
| `nav-aria-missing`                 | low      | `<nav>` element lacks `aria-label`               |

## References

- `scripts/er_audit.py` — Engagement & retention runner (Step 2).
- `scripts/http_client.py` — Shared HTTP & Playwright client.
- [Core Web Vitals — CLS](https://web.dev/cls/)
- [Google interstitial guidelines](https://developers.google.com/search/blog/2016/08/helping-users-easily-access-content-on)
