(() => {
  if (globalThis.__proChecksLoaded) return;
  globalThis.__proChecksLoaded = true;

  const uniq = (a) => [...new Set((a || []).filter(Boolean))];
  const clip = (s, n) => { n = n || 200; s = String(s || ""); return s.length > n ? s.slice(0, n) + "..." : s; };

  function countRe(text, re) {
    try {
      const flags = re.flags.indexOf("g") >= 0 ? re.flags : re.flags + "g";
      return (String(text || "").match(new RegExp(re.source, flags)) || []).length;
    } catch (e) { return 0; }
  }

  function pageSource() {
    let html = "";
    try { html = document.documentElement ? document.documentElement.outerHTML : ""; } catch (e) {}
    if (html.length > 1200000) html = html.slice(0, 1200000);
    let inline = "";
    try {
      inline = Array.from(document.scripts || []).filter((s) => !s.src).map((s) => s.textContent || "").join("\n").slice(0, 400000);
    } catch (e) {}
    return html + "\n" + inline;
  }

  const HEADERS = [
    { key: "content-security-policy", name: "Content-Security-Policy", weight: 25, severity: "medium", why: "Primary defense against XSS and script injection." },
    { key: "strict-transport-security", name: "Strict-Transport-Security (HSTS)", weight: 15, severity: "medium", why: "Forces HTTPS, blocks SSL stripping / downgrade." },
    { key: "x-frame-options", name: "X-Frame-Options", weight: 10, severity: "medium", why: "Blocks clickjacking (or CSP frame-ancestors)." },
    { key: "x-content-type-options", name: "X-Content-Type-Options", weight: 10, severity: "low", why: "Stops MIME type sniffing." },
    { key: "referrer-policy", name: "Referrer-Policy", weight: 10, severity: "low", why: "Prevents URL leakage to third parties." },
    { key: "permissions-policy", name: "Permissions-Policy", weight: 10, severity: "low", why: "Restricts camera, mic, geolocation APIs." },
    { key: "cross-origin-opener-policy", name: "Cross-Origin-Opener-Policy", weight: 10, severity: "low", why: "Isolates browsing context against XS-Leaks." },
    { key: "cross-origin-resource-policy", name: "Cross-Origin-Resource-Policy", weight: 5, severity: "low", why: "Blocks cross-origin resource reads." },
    { key: "cross-origin-embedder-policy", name: "Cross-Origin-Embedder-Policy", weight: 5, severity: "low", why: "Needed for strong cross-origin isolation." }
  ];

  async function getHeaders() {
    try {
      const res = await fetch(location.href, { method: "GET", credentials: "omit", cache: "no-store" });
      const h = {};
      res.headers.forEach((v, k) => { h[String(k).toLowerCase()] = v; });
      return { ok: true, status: res.status, headers: h };
    } catch (e) {
      return { ok: false, error: (e && e.message) || String(e) };
    }
  }

  const AUTHZ = [
    { name: "isAdmin flag", re: /isAdmin/g },
    { name: "VIP flag logic", re: /isVip|is_vip|was_vip/g },
    { name: "role comparison", re: /role\s*===|role\s*==|userRole/g },
    { name: "permission check", re: /hasAccess|canView|canEdit|isPremium|isPro/g },
    { name: "storage-based gate", re: /localStorage\.getItem\([^)]*(vip|premium|role|admin)/gi }
  ];

  const CRYPTO = [
    { name: "Math.random (weak randomness)", re: /Math\.random\s*\(/g, severity: "low" },
    { name: "MD5 usage", re: /\bmd5\s*\(/gi, severity: "medium" },
    { name: "SHA1 usage", re: /\bsha1\s*\(/gi, severity: "medium" },
    { name: "btoa on credentials", re: /btoa\s*\(\s*[^)]*(pass|token|secret)/gi, severity: "medium" },
    { name: "Client-side CryptoJS", re: /CryptoJS/g, severity: "low" }
  ];

  const PRIVACY = [
    { name: "Geolocation API", re: /navigator\.geolocation/g },
    { name: "Camera / Microphone", re: /getUserMedia/g },
    { name: "Clipboard read", re: /clipboard\.readText/g },
    { name: "Notifications", re: /requestPermission|new\s+Notification/g },
    { name: "Canvas fingerprinting", re: /toDataURL\s*\(/g },
    { name: "WebGL fingerprinting", re: /WEBGL_debug_renderer_info/g },
    { name: "Device identifier build", re: /deviceId|device_id|fingerprint/gi }
  ];

  const OWASP = [
    { id: "A01 Broken Access Control", re: /vip|admin|access|authoriz|paywall|redirect|gate/i },
    { id: "A02 Cryptographic Failures", re: /https|mixed|md5|sha1|random|crypto|jwt|token/i },
    { id: "A03 Injection", re: /xss|innerhtml|eval|document\.write|inject|sink/i },
    { id: "A05 Security Misconfiguration", re: /header|csp|cors|sourcemap|debug|iframe|sandbox|frame|cookie/i },
    { id: "A06 Vulnerable and Outdated Components", re: /librar|sri|cdn|supply|integrity|latest|third/i },
    { id: "A07 Authentication Failures", re: /password|auth|session|login|account/i },
    { id: "A08 Data Integrity Failures", re: /integrity|service worker|cache|storage/i }
  ];

  async function runProChecks(baseFindings) {
    const timeline = [];
    const findings = [];
    const text = pageSource();
    const host = location.hostname;

    // 23) Security headers
    const hr = await getHeaders();
    let headerPenalty = 0;
    const missing = [];
    const present = [];
    if (hr.ok) {
      HEADERS.forEach((spec) => {
        const val = hr.headers[spec.key];
        if (val) present.push(spec.name + ": " + clip(val, 90));
        else { missing.push(spec); headerPenalty += spec.weight; }
      });
      timeline.push({ id: "proHeaders", state: headerPenalty >= 40 ? "bad" : missing.length ? "warn" : "ok", detail: present.length + " present / " + missing.length + " missing" });
      if (present.length) findings.push({ severity: "info", title: "Security headers present", detail: "Server-side protections detected on the document response.", evidence: present.join("\n") });
      missing.forEach((m) => findings.push({ severity: m.severity, title: "Missing header: " + m.name, detail: m.why, evidence: "Not returned by " + location.origin }));
      const banner = hr.headers["server"] || hr.headers["x-powered-by"];
      if (banner) findings.push({ severity: "low", title: "Server technology disclosed", detail: "Version banners help attackers fingerprint the stack.", evidence: clip(banner, 120) });
      const cc = hr.headers["cache-control"];
      if (cc && /public/i.test(cc)) findings.push({ severity: "low", title: "Public cache-control on document", detail: "Confirm authenticated pages are not cached by shared caches.", evidence: clip(cc, 100) });
    } else {
      timeline.push({ id: "proHeaders", state: "warn", detail: "Header read failed" });
      findings.push({ severity: "info", title: "Could not read response headers", detail: "Check DevTools > Network > Response Headers manually.", evidence: clip(hr.error, 140) });
    }

    // 24) CORS posture
    const acao = hr.ok ? hr.headers["access-control-allow-origin"] : null;
    const acac = hr.ok ? hr.headers["access-control-allow-credentials"] : null;
    let corsState = "ok";
    if (acao === "*" && String(acac).toLowerCase() === "true") {
      corsState = "bad";
      findings.push({ severity: "high", title: "CORS wildcard with credentials", detail: "Allow-Origin * together with Allow-Credentials true is a critical misconfiguration.", evidence: "ACAO=" + acao + " ACAC=" + acac });
    } else if (acao) {
      corsState = "warn";
      findings.push({ severity: "low", title: "CORS policy exposed on document", detail: "Verify the allowed origin is intentional.", evidence: "ACAO=" + clip(acao, 80) + (acac ? " ACAC=" + acac : "") });
    } else {
      findings.push({ severity: "info", title: "No CORS wildcard on document response", detail: "Default same-origin behavior for this page." });
    }
    timeline.push({ id: "proCors", state: corsState, detail: acao ? "ACAO=" + clip(acao, 24) : "none" });

    // 25) Subresource Integrity
    const extScripts = Array.from(document.scripts || []).filter((s) => s.src);
    const extStyles = Array.from(document.querySelectorAll('link[rel~="stylesheet"]'));
    const noSri = [];
    extScripts.concat(extStyles).forEach((el) => {
      const url = el.src || el.href;
      if (!url) return;
      let h = null;
      try { h = new URL(url, location.href).hostname; } catch (e) {}
      if (h && h !== host && !el.getAttribute("integrity")) noSri.push(url);
    });
    timeline.push({ id: "proSri", state: noSri.length ? "warn" : "ok", detail: noSri.length + " cross-origin assets without integrity" });
    if (noSri.length) findings.push({ severity: "medium", title: "Third-party assets without SRI", detail: "Add integrity + crossorigin so a compromised CDN cannot inject code into this page.", evidence: uniq(noSri).slice(0, 12).join("\n") });
    else findings.push({ severity: "info", title: "No cross-origin assets missing SRI", detail: "Good supply-chain posture for loaded assets." });

    // 26) Supply chain surface
    const thirdHosts = uniq(extScripts.map((s) => { try { return new URL(s.src, location.href).hostname; } catch (e) { return null; } }).filter((h2) => h2 && h2 !== host));
    const unpinned = uniq(extScripts.map((s) => s.src).filter((u) => /latest/i.test(u)));
    timeline.push({ id: "proSupply", state: thirdHosts.length > 3 || unpinned.length ? "warn" : "ok", detail: thirdHosts.length + " third-party script hosts" });
    findings.push({ severity: thirdHosts.length > 3 ? "low" : "info", title: "Third-party script execution surface", detail: "Every third-party host can run JavaScript in this page origin.", evidence: thirdHosts.join("\n") || "(none)" });
    if (unpinned.length) findings.push({ severity: "medium", title: "Unpinned CDN version detected", detail: "Pin exact versions; latest tags can change code silently.", evidence: unpinned.slice(0, 8).join("\n") });

    // 27) Client-side authorization (OWASP A01)
    const authzHits = AUTHZ.map((a) => ({ name: a.name, count: countRe(text, a.re) })).filter((x) => x.count > 0);
    timeline.push({ id: "proAuthz", state: authzHits.length ? "warn" : "ok", detail: authzHits.length ? authzHits.map((x) => x.name).join(", ") : "no client gates found" });
    if (authzHits.length) findings.push({ severity: "medium", title: "Client-side authorization logic (OWASP A01)", detail: "UI gating is acceptable, but the server or database rules must enforce the same restriction independently.", evidence: authzHits.map((x) => x.name + " x " + x.count).join("\n") });
    else findings.push({ severity: "info", title: "No obvious client-side permission gates", detail: "Authorization may be fully server-side, which is preferred." });

    // 28) Cryptography quality
    const cryptoHits = CRYPTO.map((c) => ({ name: c.name, severity: c.severity, count: countRe(text, c.re) })).filter((x) => x.count > 0);
    timeline.push({ id: "proCrypto", state: cryptoHits.some((c) => c.severity === "medium") ? "warn" : "ok", detail: cryptoHits.length ? cryptoHits.map((c) => c.name).join(", ") : "no weak primitives found" });
    cryptoHits.forEach((c) => findings.push({ severity: c.severity, title: "Crypto review: " + c.name, detail: "Use crypto.getRandomValues and SHA-256+ for security-relevant values.", evidence: c.name + " x " + c.count }));

    // 29) Privacy / powerful APIs
    const privHits = PRIVACY.map((p) => ({ name: p.name, count: countRe(text, p.re) })).filter((x) => x.count > 0);
    timeline.push({ id: "proPrivacy", state: privHits.length ? "warn" : "ok", detail: privHits.length + " powerful API signals" });
    if (privHits.length) findings.push({ severity: "low", title: "Powerful browser APIs referenced", detail: "Confirm user consent and Permissions-Policy restrictions for these APIs.", evidence: privHits.map((p) => p.name + " x " + p.count).join("\n") });

    // 30) Sensitive data at rest
    let totalBytes = 0;
    const risky = [];
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        const v = localStorage.getItem(k) || "";
        totalBytes += (k || "").length + v.length;
        if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(v)) risky.push(k + " -> email-like value");
        if (/eyJ[A-Za-z0-9_-]{10,}\./.test(v)) risky.push(k + " -> token-like value");
        if (/\d{13,19}/.test(v.replace(/\s|-/g, ""))) risky.push(k + " -> long numeric sequence");
        if (v.length > 20000) risky.push(k + " -> large cached payload (" + Math.round(v.length / 1024) + " KB)");
      }
    } catch (e) {}
    timeline.push({ id: "proStorage", state: risky.length ? "warn" : "ok", detail: Math.round(totalBytes / 1024) + " KB stored, " + risky.length + " flags" });
    findings.push({ severity: risky.length ? "medium" : "info", title: "Client data-at-rest review", detail: "localStorage is readable by any script in this origin, so XSS equals data theft.", evidence: (risky.slice(0, 12).join("\n") || "No sensitive patterns") + "\ntotal=" + Math.round(totalBytes / 1024) + " KB" });

    // 31) Firebase configuration inventory
    const cfgKeys = ["apiKey", "authDomain", "projectId", "storageBucket", "messagingSenderId", "appId", "measurementId", "databaseURL"];
    const cfg = {};
    cfgKeys.forEach((k) => {
      try {
        const m = text.match(new RegExp(k + "[^A-Za-z0-9]{1,4}([A-Za-z0-9_.:@%/-]{6,})"));
        if (m) cfg[k] = clip(m[1], 60);
      } catch (e) {}
    });
    const cfgFound = Object.keys(cfg);
    timeline.push({ id: "proFirebase", state: cfgFound.length ? "warn" : "ok", detail: cfgFound.length + " config fields" });
    if (cfgFound.length) {
      findings.push({ severity: "info", title: "Firebase client configuration inventory", detail: "These values are public by design. Security depends entirely on Firestore/Storage Rules and Auth, not on hiding them.", evidence: cfgFound.map((k) => k + " = " + cfg[k]).join("\n") });
      if (cfg.storageBucket) findings.push({ severity: "medium", title: "Storage bucket referenced in client", detail: "Verify Storage Rules require auth and entitlement for paid files, and prefer signed URLs.", evidence: "storageBucket = " + cfg.storageBucket });
      if (cfg.databaseURL) findings.push({ severity: "medium", title: "Realtime Database URL referenced", detail: "Confirm RTDB rules are not open for read/write.", evidence: "databaseURL = " + cfg.databaseURL });
    }

    // 32) OWASP mapping + professional risk grade
    const all = (baseFindings || []).concat(findings);
    const sev = { high: 0, medium: 0, low: 0, info: 0 };
    all.forEach((f) => { sev[f.severity] = (sev[f.severity] || 0) + 1; });
    const owaspCounts = OWASP.map((c) => {
      const n = all.filter((f) => f.severity !== "info" && (c.re.test(f.title || "") || c.re.test(f.detail || ""))).length;
      return { id: c.id, count: n };
    }).filter((c) => c.count > 0);

    let score = 100 - (sev.high * 15 + sev.medium * 6 + sev.low * 2) - Math.round(headerPenalty * 0.35);
    if (score < 0) score = 0;
    let grade = "F";
    if (score >= 95) grade = "A+";
    else if (score >= 88) grade = "A";
    else if (score >= 78) grade = "B";
    else if (score >= 68) grade = "C";
    else if (score >= 55) grade = "D";
    else if (score >= 40) grade = "E";

    timeline.push({ id: "proSummary", state: grade === "F" || grade === "E" ? "bad" : score < 88 ? "warn" : "ok", detail: "Grade " + grade + " (" + score + "/100)" });
    findings.push({
      severity: "info",
      title: "Professional risk grade: " + grade + " (" + score + "/100)",
      detail: "Weighted score from severity counts and missing security headers. Heuristic, not a penetration test.",
      evidence: "High " + sev.high + " | Medium " + sev.medium + " | Low " + sev.low + " | Info " + sev.info + "\nOWASP mapping:\n" + (owaspCounts.map((c) => c.id + ": " + c.count).join("\n") || "none")
    });

    return { ok: true, timeline: timeline, findings: findings, meta: { score: score, grade: grade, owasp: owaspCounts, headerPenalty: headerPenalty, firebaseConfig: cfg } };
  }

  globalThis.__runProChecks = runProChecks;
})();
