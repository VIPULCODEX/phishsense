# Phish Sense Browser Extension

Realtime scam/phishing assessment for web pages.

## What It Does
- Auto-scans page text and links when a page loads.
- Re-scans dynamic pages (SPA/infinite-scroll) using a debounced observer.
- Detects risk indicators:
  - urgency language
  - OTP solicitation
  - account-verification pressure
  - lottery/job/fee lures
  - obfuscated words (`cl1ck`, `0tp`, `fr33`)
  - suspicious URLs (shorteners, random domains, suspicious TLDs, IP/punycode hosts)
  - deceptive anchor-text mismatch
- Shows:
  - floating risk widget on page
  - popup summary with risk bar, prediction, reasons
- Uses local analysis only (no external API calls).

## Install in Chrome
1. Open `chrome://extensions/`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select folder: `project/browser-extension`

## Usage
1. Open any website.
2. You will see `Phish Sense` widget in top-right with risk score.
3. Click extension icon for detailed summary.
4. Use popup toggle to enable/disable scanning globally.

## Notes
- This extension is heuristic and context-based; it is not a replacement for enterprise secure browsing tools.
- For best results, combine it with URL reputation services and browser Safe Browsing protections.

