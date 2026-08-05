# Web Public Security Scanner

Browser extension (Chrome / Edge / Brave — Manifest V3) that runs a **step-by-step, read-only security check** on the **currently open website**.

It only inspects what the browser can already see publicly:
- page HTML / scripts / links / forms
- mixed content clues
- common client-side secret patterns
- API / endpoint URLs found in public source
- basic cookie / storage / HTTPS status

> **Defensive tool only.** It does not exploit, bypass logins, brute-force, or attack servers.

## Features

1. **Step-by-step scan** with live status
2. **HTTPS / mixed content** checks
3. **Public scripts & external domains** inventory
4. **API / endpoint discovery** from page source (fetch/XHR/Firebase/etc. patterns)
5. **Exposed secret pattern** heuristics (API keys, tokens) — false positives possible
6. **Forms / password fields / autocomplete** notes
7. **Local/session storage keys** (names only)
8. **Export JSON report**

## Install (unpacked)

1. Clone this repo:
   ```bash
   git clone https://github.com/abdelouahabmostafaetu-bot/web-public-security-scanner.git
   ```
2. Open Chrome/Edge → `chrome://extensions`
3. Enable **Developer mode**
4. **Load unpacked** → select the `extension/` folder
5. Open any website → click the extension icon → **Start scan**

## Use on takamol.web.app (example)

1. Open https://takamol.web.app/
2. Open the extension popup
3. Click **Start scan**
4. Watch steps 1→N and the final status summary
5. Optionally **Export JSON**

## Project layout

```text
extension/
  manifest.json
  popup.html
  popup.css
  popup.js
  content.js
  icons/
    icon16.png
    icon48.png
    icon128.png
```

## Legal / ethics

- Scan only sites you own or are allowed to test.
- Do not use findings to attack or scrape private/paid content.
- Report real issues responsibly to the owner.

## License

MIT
