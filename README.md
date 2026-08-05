# Web Public Security Scanner v1.4

Professional, read-only browser extension that reviews the **public client-side security posture** of the page you are on.

Repo: https://github.com/abdelouahabmostafaetu-bot/web-public-security-scanner

## What it does (32 checks)

### Baseline (1-22)
HTTPS, CSP meta, assets + Service Worker, JS libraries, API URLs, Firebase clues, secret patterns, PDF/Storage links, account & VIP flags, JWT in storage, forms, dangerous links, DOM XSS sinks, eval/document.write, admin/debug paths, source maps, emails, iframes, cookies, paywall UI, mixed content, baseline summary.

### Professional module (23-32)
| # | Check | Standard |
|---|-------|----------|
| 23 | Security headers (CSP, HSTS, XFO, XCTO, Referrer, Permissions, COOP/CORP/COEP) | securityheaders-style grading |
| 24 | CORS posture (wildcard + credentials) | OWASP A05 |
| 25 | Subresource Integrity on third-party assets | OWASP A08 |
| 26 | Supply-chain surface, unpinned CDN versions | OWASP A06 |
| 27 | Client-side authorization gates (isVip/isAdmin/role) | OWASP A01 |
| 28 | Crypto quality (Math.random, MD5, SHA1, btoa) | OWASP A02 |
| 29 | Powerful APIs (geolocation, camera, clipboard, fingerprinting) | Privacy |
| 30 | Sensitive data at rest in localStorage | OWASP A02/A08 |
| 31 | Firebase config audit (storageBucket, databaseURL) | Cloud posture |
| 32 | OWASP Top 10 mapping + weighted risk grade A+ to F | Reporting |

## Install / update

```bash
git pull
```

1. Open `chrome://extensions`
2. Enable Developer mode
3. Load unpacked -> select `extension/`
4. After each update press **Reload**, then hard refresh the site (Ctrl+Shift+R)
5. Click the extension -> **Start scan** -> **Export JSON** for the report

## How to add your own test

1. Add a step id + title in `popup.js` -> `STEP_DEFS`
2. Implement the logic in `extension/pro-checks.js` (professional) or `extension/content.js` (baseline)
3. Push `timeline.push({ id, state, detail })` and `findings.push({ severity, title, detail, evidence })`
4. Bump `version` in `manifest.json`, commit, reload the extension

## Scope and ethics

- Read-only. It never exploits, brute-forces, or bypasses authentication or paywalls.
- All results are **heuristics** and may contain false positives.
- A public Firebase `apiKey`/`projectId` is normal; real protection comes from Firestore/Storage Rules and Auth.
- Only scan sites you own or are authorized to review.

## Reference tools that inspired the checks

- Retire.js (vulnerable JS libraries)
- Gitleaks / TruffleHog (secret detection rules)
- Nuclei templates (misconfiguration heuristics)
- OWASP Web Security Testing Guide (WSTG) and OWASP Top 10 2021

## License

MIT
