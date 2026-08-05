# Web Public Security Scanner

Browser extension (Chrome / Edge / Brave — Manifest V3) for **step-by-step, read-only** security checks on the **currently open website**.

> Defensive tool only. Does **not** exploit, bypass logins, or attack servers.

## Repo
https://github.com/abdelouahabmostafaetu-bot/web-public-security-scanner

## Version 1.1 checks (step-by-step)

1. HTTPS / origin  
2. Meta / CSP / generator / referrer  
3. Scripts, styles, images, **Service Worker**  
4. Public API / backend URL discovery (fonts de-prioritized)  
5. **Firebase / web.app indicators**  
6. Secret pattern heuristics (API keys, JWT, Stripe, PEM, …)  
7. **Public PDF / Storage / blob link detection**  
8. Forms & password fields  
9. **localStorage / sessionStorage analysis (VIP flags, auth keys)**  
10. Visible cookies (`document.cookie`)  
11. **Paywall / VIP UI heuristics**  
12. Mixed content  
13. Final status + JSON export  

## Install

```bash
git clone https://github.com/abdelouahabmostafaetu-bot/web-public-security-scanner.git
cd web-public-security-scanner
```

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select `extension/`
4. Open a site → click extension → **Start scan**
5. After code updates: click **Reload** on the extension card

## How to add more tests (method)

1. Add a new step id in `extension/popup.js` → `STEP_DEFS`
2. Implement the check inside `runScan()` in `extension/content.js`
3. `timeline.push({ id, state, detail })`
4. `findings.push({ severity, title, detail, evidence })`
5. Bump `version` in `manifest.json` + report JSON
6. Commit & push; reload extension

### Ideas for v1.2+
- Optional `chrome.debugger` / declarativeNetRequest observations (advanced)
- Permission-denied fingerprint tips for Firestore webchannel
- Click-helper mode: “listen 10s for new PDF requests”
- i18n Arabic UI
- Export markdown report

## Legal / ethics
Scan sites you own or have permission to test. Do not use findings to attack or bypass paid access.

## License
MIT
