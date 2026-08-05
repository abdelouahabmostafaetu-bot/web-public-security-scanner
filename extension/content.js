(() => {
  // Always reload latest scanner logic when reinjected
  window.__publicSecurityScannerLoaded = true;

  const SECRET_PATTERNS = [
    { name: "Google API key", re: /AIza[0-9A-Za-z\-_]{20,}/g, severity: "high" },
    { name: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/g, severity: "high" },
    { name: "Generic bearer/jwt-like", re: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, severity: "medium" },
    { name: "Firebase/apiKey assignment", re: /apiKey\s*[:=]\s*[\"'][^\"']+[\"']/gi, severity: "medium" },
    { name: "Private key PEM header", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "high" },
    { name: "Slack token-like", re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: "high" },
    { name: "GitHub PAT-like", re: /gh[pousr]_[A-Za-z0-9_]{20,}/g, severity: "high" },
    { name: "Stripe secret-like", re: /sk_live_[0-9a-zA-Z]{16,}/g, severity: "high" },
    { name: "Stripe publishable key", re: /pk_live_[0-9a-zA-Z]{16,}/g, severity: "low" },
    { name: "SendGrid/Twilio-like key", re: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, severity: "high" },
    { name: "OpenAI-like key", re: /sk-[A-Za-z0-9]{20,}/g, severity: "high" },
    { name: "Hardcoded password assignment", re: /password\s*[:=]\s*[\"'][^\"']{4,}[\"']/gi, severity: "medium" }
  ];

  const ENDPOINT_REGEXES = [
    /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?\/[\w\-./?%&=+#]*/g,
    /[\"'`](\/api\/[\w\-./?%&=]*)[\"'`]/g,
    /[\"'`](\/v[0-9]+\/[\w\-./?%&=]*)[\"'`]/g,
    /firebaseio\.com|firestore\.googleapis\.com|identitytoolkit\.googleapis\.com|securetoken\.googleapis\.com|cloudfunctions\.net|supabase\.co|amazonaws\.com|firebasestorage\.googleapis\.com/gi
  ];

  const PDF_LINK_RE = /https?:\/\/[^\"'\s>]+?\.pdf(?:\?[^\"'\s>]*)?|blob:https?:\/\/[^\"'\s>]+|https?:\/\/firebasestorage\.googleapis\.com\/[^\"'\s>]+|https?:\/\/storage\.googleapis\.com\/[^\"'\s>]+/gi;

  function uniq(arr) {
    return [...new Set(arr.filter(Boolean))];
  }

  function clip(s, n = 180) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n) + "…" : s;
  }

  function getInlineAndExternalScripts() {
    const scripts = [...document.scripts];
    return {
      total: scripts.length,
      external: scripts.filter((s) => s.src).map((s) => s.src),
      inlineCount: scripts.filter((s) => !s.src).length,
      inlineText: scripts.filter((s) => !s.src).map((s) => s.textContent || "").join("\n")
    };
  }

  function collectPublicSource() {
    const html = document.documentElement?.outerHTML || "";
    const scripts = getInlineAndExternalScripts();
    return {
      html,
      scripts,
      combined: html + "\n" + scripts.inlineText
    };
  }

  function findEndpoints(text) {
    const found = [];
    for (const re of ENDPOINT_REGEXES) {
      const copy = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
      let m;
      while ((m = copy.exec(text)) !== null) found.push(m[1] || m[0]);
    }
    return uniq(found).slice(0, 100);
  }

  function findSecrets(text) {
    const hits = [];
    for (const p of SECRET_PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
      const matches = text.match(re) || [];
      uniq(matches).slice(0, 5).forEach((val) => {
        hits.push({ type: p.name, severity: p.severity, sample: clip(val, 48) });
      });
    }
    return hits;
  }

  function domainOf(url) {
    try { return new URL(url, location.href).hostname; } catch { return null; }
  }

  function analyzeStorage() {
    const localEntries = [];
    const sessionEntries = [];
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        const v = localStorage.getItem(k);
        localEntries.push({ key: k, valuePreview: clip(v, 80), len: (v || "").length });
      }
    } catch {}
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        const v = sessionStorage.getItem(k);
        sessionEntries.push({ key: k, valuePreview: clip(v, 80), len: (v || "").length });
      }
    } catch {}

    const vipKeys = localEntries.filter((e) => /vip|premium|pro|subscri|plan|entitlement|was_vip/i.test(e.key));
    const authishKeys = localEntries.filter((e) => /token|auth|session|uid|user|jwt|firebase:authUser/i.test(e.key));
    const cacheKeys = localEntries.filter((e) => /cache|exam|content/i.test(e.key));

    const vipFlags = vipKeys.map((e) => {
      const raw = (e.valuePreview || "").trim().toLowerCase();
      let parsed = raw;
      try { parsed = JSON.parse(localStorage.getItem(e.key)); } catch {}
      return { key: e.key, value: String(parsed), truthy: parsed === true || parsed === "true" || parsed === 1 || parsed === "1" };
    });

    return { localEntries, sessionEntries, vipKeys, authishKeys, cacheKeys, vipFlags };
  }

  function analyzeCookies() {
    const raw = document.cookie || "";
    if (!raw) return { count: 0, names: [], notes: ["No document.cookie values visible (httpOnly cookies stay hidden — good for secrets)."] };
    const parts = raw.split(";").map((x) => x.trim()).filter(Boolean);
    const names = parts.map((p) => p.split("=")[0]);
    return {
      count: parts.length,
      names,
      notes: [
        "Only non-httpOnly cookies are visible to page JS.",
        "Sensitive session tokens should preferably be httpOnly + Secure + SameSite."
      ]
    };
  }

  function analyzePaywall(text) {
    const bodyText = (document.body?.innerText || "").slice(0, 20000);
    const patterns = [
      /\bVIP\b/i,
      /premium/i,
      /subscribe|subscription|اشتراك/i,
      /paywall|locked|مقفل|🔒/i,
      /upgrade|pro plan|compte vip|حساب\s*vip/i,
      /paypal|stripe|cib|ccp|بريدي\s*موب/i
    ];
    const hits = patterns.filter((re) => re.test(bodyText) || re.test(text)).map((re) => String(re));
    const lockButtons = [...document.querySelectorAll("button, a, [role=button]")]
      .map((el) => (el.innerText || el.textContent || "").trim())
      .filter((t) => t && /vip|premium|subscribe|اشتراك|مقفل|🔒|pro/i.test(t))
      .slice(0, 20);
    return { hits, lockButtons, likelyPaywall: hits.length >= 2 || lockButtons.length > 0 };
  }

  function findPdfLinks(text) {
    const fromText = text.match(PDF_LINK_RE) || [];
    const fromAnchors = [...document.querySelectorAll("a[href]")].map((a) => a.href).filter((h) => /\.pdf|firebasestorage|storage\.googleapis|blob:/i.test(h));
    const fromEmbeds = [...document.querySelectorAll("embed[src], iframe[src], object[data]")]
      .map((el) => el.src || el.data)
      .filter((h) => h && /\.pdf|blob:|storage/i.test(h));
    return uniq([...fromText, ...fromAnchors, ...fromEmbeds]).slice(0, 40);
  }

  async function runScan() {
    const timeline = [];
    const findings = [];
    const startedAt = new Date().toISOString();
    const src = collectPublicSource();

    // 1 HTTPS
    const isHttps = location.protocol === "https:";
    timeline.push({ id: "https", state: isHttps ? "ok" : "bad", detail: isHttps ? `HTTPS OK (${location.origin})` : `Not HTTPS: ${location.protocol}` });
    findings.push(isHttps
      ? { severity: "info", title: "HTTPS enabled", detail: "The page origin uses HTTPS.", evidence: location.origin }
      : { severity: "high", title: "Page is not served over HTTPS", detail: "Data and cookies can be exposed on the network.", evidence: location.href });

    // 2 Meta / CSP
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]')?.content || null;
    const generator = document.querySelector('meta[name="generator" i]')?.content || null;
    const robots = document.querySelector('meta[name="robots" i]')?.content || null;
    const referrer = document.querySelector('meta[name="referrer" i]')?.content || null;
    timeline.push({ id: "meta", state: cspMeta ? "ok" : "warn", detail: cspMeta ? "CSP meta tag found" : "No CSP meta tag (header CSP unknown from page JS)" });
    if (!cspMeta) findings.push({ severity: "low", title: "No Content-Security-Policy meta tag", detail: "CSP may still be set via HTTP headers (not readable from page JS). Check DevTools → Network → Response Headers." });
    else findings.push({ severity: "info", title: "CSP meta present", detail: "A CSP meta tag was found in public HTML.", evidence: clip(cspMeta, 220) });
    if (generator) findings.push({ severity: "info", title: "Generator meta", detail: generator });
    if (robots) findings.push({ severity: "info", title: "Robots meta", detail: robots });
    if (referrer) findings.push({ severity: "info", title: "Referrer policy meta", detail: referrer });

    // 3 Assets + service worker
    const scripts = src.scripts;
    const styles = [...document.querySelectorAll('link[rel~="stylesheet"]')].map((l) => l.href);
    const images = [...document.images].map((i) => i.currentSrc || i.src).filter(Boolean);
    const externalDomains = uniq([
      ...scripts.external.map(domainOf),
      ...styles.map(domainOf),
      ...images.map(domainOf)
    ].filter((d) => d && d !== location.hostname));
    let swCount = 0;
    try {
      if (navigator.serviceWorker) {
        const regs = await navigator.serviceWorker.getRegistrations();
        swCount = regs.length;
      }
    } catch {}
    timeline.push({ id: "assets", state: "ok", detail: `${scripts.total} scripts, ${styles.length} styles, ${externalDomains.length} 3rd-party domains, SW=${swCount}` });
    findings.push({
      severity: "info",
      title: "Public asset inventory",
      detail: `Scripts: ${scripts.total} total / ${scripts.inlineCount} inline / ${scripts.external.length} external. Styles: ${styles.length}. Third-party domains: ${externalDomains.length}. ServiceWorkers: ${swCount}.`,
      evidence: externalDomains.slice(0, 25).join("\n") || "(none)"
    });
    if (swCount > 0) {
      findings.push({
        severity: "info",
        title: "Service Worker registered",
        detail: "Caching may hide network downloads (PDF/API may come from cache). Disable cache or use hard reload when testing."
      });
    }

    // 4 Endpoints
    const endpoints = findEndpoints(src.combined);
    const interesting = endpoints.filter((u) =>
      /api|firebase|firestore|supabase|cloudfunctions|graphql|auth|token|login|paypal|stripe|zoom|googleapis|webchannel|gsessionid/i.test(u)
    );
    // Reduce false positives from pure font CDNs in "interesting" medium bucket
    const interestingNoFonts = interesting.filter((u) => !/fonts\.googleapis|fonts\.gstatic|woff2?/i.test(u));
    timeline.push({ id: "endpoints", state: interestingNoFonts.length ? "warn" : "ok", detail: `${endpoints.length} URLs found, ${interestingNoFonts.length} API/auth-like (fonts excluded)` });
    if (interestingNoFonts.length) {
      findings.push({
        severity: "medium",
        title: "Possible public API / backend endpoints referenced",
        detail: "Found in public HTML/JS. Review auth rules and over-exposed config. Fonts CDNs were de-prioritized.",
        evidence: interestingNoFonts.slice(0, 25).join("\n")
      });
    } else {
      findings.push({
        severity: "low",
        title: "Few/no strong API endpoint strings",
        detail: "No strong API/auth URL patterns were found in public source (they may load dynamically via Firestore webchannel)."
      });
    }

    // 5 Firebase
    const firebaseClues = uniq((
      src.combined.match(/[a-z0-9-]+\.firebaseapp\.com|[a-z0-9-]+\.web\.app|firebaseio\.com|initializeApp\s*\(|firebase-app\.js|firebase-auth\.js|firebase-firestore\.js|firebasestorage/gi) || []
    ));
    const onFirebaseHost = /\.web\.app$|\.firebaseapp\.com$/i.test(location.hostname);
    timeline.push({ id: "firebase", state: (firebaseClues.length || onFirebaseHost) ? "warn" : "ok", detail: onFirebaseHost ? "Hosted on Firebase Hosting hostname" : (firebaseClues.length ? `${firebaseClues.length} Firebase clues` : "No Firebase clues") });
    if (onFirebaseHost || firebaseClues.length) {
      findings.push({
        severity: "info",
        title: "Firebase stack indicators",
        detail: "Ensure Firestore/Storage security rules enforce VIP/auth server-side. Client flags are not enough.",
        evidence: [`host=${location.hostname}`, ...firebaseClues.slice(0, 20)].join("\n")
      });
    }

    // 6 Secrets
    const secrets = findSecrets(src.combined);
    timeline.push({ id: "secrets", state: secrets.some((s) => s.severity === "high") ? "bad" : secrets.length ? "warn" : "ok", detail: secrets.length ? `${secrets.length} potential secret pattern(s)` : "No common secret patterns detected" });
    secrets.forEach((s) => findings.push({
      severity: s.severity,
      title: `Possible exposed secret: ${s.type}`,
      detail: "Heuristic match in public page source. Verify manually; false positives happen. Rotate if real.",
      evidence: s.sample
    }));

    // 7 PDF / storage links
    const pdfLinks = findPdfLinks(src.combined);
    const publicPdf = pdfLinks.filter((u) => /^https?:/i.test(u) && !u.startsWith("blob:"));
    const blobPdf = pdfLinks.filter((u) => u.startsWith("blob:"));
    timeline.push({ id: "pdf", state: publicPdf.length ? "warn" : "ok", detail: publicPdf.length ? `${publicPdf.length} public-looking PDF/storage URL(s)` : (blobPdf.length ? `${blobPdf.length} blob: link(s) (print/generated)` : "No direct PDF/storage URLs in public source") });
    if (publicPdf.length) {
      findings.push({
        severity: "medium",
        title: "Public PDF / cloud storage URLs found in page source",
        detail: "Test in Incognito whether these open without auth. Prefer signed URLs + Storage rules for paid files.",
        evidence: publicPdf.slice(0, 15).join("\n")
      });
    } else {
      findings.push({
        severity: "info",
        title: "No direct public PDF URL detected in source",
        detail: "Site may use print-to-PDF, blob generation, or fetch PDFs only after click. Re-scan after clicking download and check Network."
      });
    }
    if (blobPdf.length) {
      findings.push({
        severity: "low",
        title: "blob: URLs present",
        detail: "Usually temporary in-browser files (print/export), not stable public internet links.",
        evidence: blobPdf.slice(0, 10).join("\n")
      });
    }

    // 8 Forms
    const forms = [...document.forms].map((f, idx) => ({
      index: idx,
      action: f.action || "(same page)",
      method: (f.method || "get").toUpperCase(),
      hasPassword: !!f.querySelector('input[type="password"]')
    }));
    const insecurePasswordForm = forms.find((f) => f.hasPassword && !String(f.action).startsWith("https:") && location.protocol !== "https:");
    timeline.push({ id: "forms", state: insecurePasswordForm ? "bad" : "ok", detail: `${forms.length} form(s), ${forms.filter((f) => f.hasPassword).length} with password field` });
    if (forms.length) findings.push({ severity: forms.some((f) => f.hasPassword) ? "info" : "low", title: "Public forms detected", detail: "Review form actions and HTTPS.", evidence: forms.slice(0, 10).map((f) => `#${f.index} ${f.method} ${f.action} password=${f.hasPassword}`).join("\n") });
    if (insecurePasswordForm) findings.push({ severity: "high", title: "Password form on non-HTTPS context", detail: "Credentials may be exposed in transit.", evidence: insecurePasswordForm.action });

    // 9 Storage / VIP
    const storage = analyzeStorage();
    timeline.push({ id: "storage", state: storage.vipKeys.length ? "warn" : "ok", detail: `local=${storage.localEntries.length}, session=${storage.sessionEntries.length}, vipKeys=${storage.vipKeys.length}` });
    findings.push({
      severity: "info",
      title: "Browser storage inventory (names + short previews)",
      detail: "Values truncated. Secrets should not rely on localStorage alone.",
      evidence: [
        "localStorage keys:",
        ...storage.localEntries.slice(0, 25).map((e) => `${e.key} = ${e.valuePreview}`),
        "sessionStorage keys:",
        ...storage.sessionEntries.slice(0, 15).map((e) => `${e.key} = ${e.valuePreview}`)
      ].join("\n") || "(empty)"
    });
    if (storage.vipFlags.length) {
      const anyTrue = storage.vipFlags.some((v) => v.truthy);
      findings.push({
        severity: "medium",
        title: "Client-side VIP/subscription flag(s) in localStorage",
        detail: anyTrue
          ? "At least one VIP-like flag is truthy in the browser. Ensure server/Firebase still authorizes paid content."
          : "VIP-like flag(s) present and currently false/locked. Good UI signal; still verify server-side enforcement.",
        evidence: storage.vipFlags.map((v) => `${v.key}=${v.value}`).join("\n")
      });
    }
    if (storage.authishKeys.length) {
      findings.push({
        severity: "low",
        title: "Auth/session-related storage keys",
        detail: "Tokens in localStorage are XSS-stealable. Prefer httpOnly cookies or short-lived tokens where possible.",
        evidence: storage.authishKeys.map((e) => e.key).join(", ")
      });
    }

    // 10 Cookies
    const cookies = analyzeCookies();
    timeline.push({ id: "cookies", state: "ok", detail: `${cookies.count} visible document.cookie value(s)` });
    findings.push({
      severity: "info",
      title: "Visible cookies (document.cookie)",
      detail: cookies.notes.join(" "),
      evidence: cookies.names.slice(0, 30).join(", ") || "(none visible)"
    });

    // 11 Paywall heuristics
    const paywall = analyzePaywall(src.combined);
    timeline.push({ id: "paywall", state: paywall.likelyPaywall ? "ok" : "ok", detail: paywall.likelyPaywall ? "Paywall/VIP UI signals detected" : "No strong paywall wording detected on this page" });
    if (paywall.likelyPaywall) {
      findings.push({
        severity: "info",
        title: "Paywall / VIP UI heuristics",
        detail: "Page mentions VIP/subscribe/lock patterns. Combine with storage VIP flags + Network denied responses for full assessment.",
        evidence: [`buttons: ${paywall.lockButtons.slice(0, 10).join(" | ") || "(none)"}`, `patterns: ${paywall.hits.length}`].join("\n")
      });
    }

    // 12 Mixed content
    const activeMixed = [];
    if (isHttps) {
      [...scripts.external, ...styles, ...images].forEach((u) => {
        if (typeof u === "string" && u.startsWith("http://")) activeMixed.push(u);
      });
    }
    timeline.push({ id: "mixed", state: activeMixed.length ? "bad" : "ok", detail: activeMixed.length ? `${activeMixed.length} http:// asset(s) on https page` : "No active mixed-content assets detected" });
    if (activeMixed.length) {
      findings.push({ severity: "high", title: "Mixed content assets", detail: "HTTPS page loads HTTP resources.", evidence: uniq(activeMixed).slice(0, 20).join("\n") });
    }

    // 13 Summary
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    let status = "Healthy";
    let state = "ok";
    if (counts.high > 0) { status = "Issues found"; state = "bad"; }
    else if (counts.medium > 0) { status = "Review recommended"; state = "warn"; }
    timeline.push({ id: "summary", state, detail: `${status} · high=${counts.high} medium=${counts.medium} low=${counts.low} info=${counts.info}` });

    const order = { high: 0, medium: 1, low: 2, info: 3 };
    findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

    return {
      ok: true,
      timeline,
      report: {
        tool: "web-public-security-scanner",
        version: "1.1.0",
        startedAt,
        finishedAt: new Date().toISOString(),
        url: location.href,
        origin: location.origin,
        status,
        counts,
        inventory: {
          scriptsTotal: scripts.total,
          scriptsExternal: scripts.external.length,
          scriptsInline: scripts.inlineCount,
          styles: styles.length,
          thirdPartyDomains: externalDomains,
          serviceWorkers: swCount,
          endpointsFound: endpoints.length,
          interestingEndpoints: interestingNoFonts.length,
          pdfLinks: pdfLinks.length,
          forms: forms.length,
          vipFlags: storage.vipFlags
        },
        endpoints: interestingNoFonts.slice(0, 50),
        pdfLinks: pdfLinks.slice(0, 30),
        findings
      }
    };
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type !== "RUN_PUBLIC_SECURITY_SCAN") return;
    runScan()
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err?.message || String(err) }));
    return true;
  });
})();
