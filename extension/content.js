(() => {
  if (window.__publicSecurityScannerLoaded) return;
  window.__publicSecurityScannerLoaded = true;

  const SECRET_PATTERNS = [
    { name: "Google API key", re: /AIza[0-9A-Za-z\-_]{20,}/g, severity: "high" },
    { name: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/g, severity: "high" },
    { name: "Generic bearer/jwt-like", re: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, severity: "medium" },
    { name: "Firebase-looking config block", re: /apiKey\s*[:=]\s*[\"'][^\"']+[\"']/gi, severity: "medium" },
    { name: "Private key PEM header", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "high" },
    { name: "Slack token-like", re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: "high" },
    { name: "GitHub PAT-like", re: /gh[pousr]_[A-Za-z0-9_]{20,}/g, severity: "high" }
  ];

  const ENDPOINT_REGEXES = [
    /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?\/[\w\-./?%&=+#]*/g,
    /[\"'`](\/api\/[\w\-./?%&=]*)[\"'`]/g,
    /[\"'`](\/v[0-9]+\/[\w\-./?%&=]*)[\"'`]/g,
    /firebaseio\.com|firestore\.googleapis\.com|identitytoolkit\.googleapis\.com|securetoken\.googleapis\.com|cloudfunctions\.net|supabase\.co|amazonaws\.com/gi
  ];

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
      while ((m = copy.exec(text)) !== null) {
        found.push(m[1] || m[0]);
      }
    }
    return uniq(found).slice(0, 80);
  }

  function findSecrets(text) {
    const hits = [];
    for (const p of SECRET_PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
      const matches = text.match(re) || [];
      uniq(matches).slice(0, 5).forEach((val) => {
        hits.push({
          type: p.name,
          severity: p.severity,
          sample: clip(val, 48)
        });
      });
    }
    return hits;
  }

  function domainOf(url) {
    try { return new URL(url, location.href).hostname; } catch { return null; }
  }

  async function runScan() {
    const timeline = [];
    const findings = [];
    const startedAt = new Date().toISOString();
    const src = collectPublicSource();

    // 1) HTTPS
    const isHttps = location.protocol === "https:";
    timeline.push({
      id: "https",
      state: isHttps ? "ok" : "bad",
      detail: isHttps ? `HTTPS OK (${location.origin})` : `Not HTTPS: ${location.protocol}`
    });
    if (!isHttps) {
      findings.push({
        severity: "high",
        title: "Page is not served over HTTPS",
        detail: "Data and cookies can be exposed on the network.",
        evidence: location.href
      });
    } else {
      findings.push({
        severity: "info",
        title: "HTTPS enabled",
        detail: "The page origin uses HTTPS.",
        evidence: location.origin
      });
    }

    // 2) Meta / CSP clues
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]')?.content || null;
    const generator = document.querySelector('meta[name="generator" i]')?.content || null;
    const robots = document.querySelector('meta[name="robots" i]')?.content || null;
    timeline.push({
      id: "meta",
      state: cspMeta ? "ok" : "warn",
      detail: cspMeta ? "CSP meta tag found" : "No CSP meta tag (header CSP unknown from page JS)"
    });
    if (!cspMeta) {
      findings.push({
        severity: "low",
        title: "No Content-Security-Policy meta tag",
        detail: "CSP may still be set via HTTP headers (not readable from page JS). Worth verifying in DevTools → Network."
      });
    } else {
      findings.push({
        severity: "info",
        title: "CSP meta present",
        detail: "A CSP meta tag was found in public HTML.",
        evidence: clip(cspMeta, 220)
      });
    }
    if (generator) {
      findings.push({ severity: "info", title: "Generator meta", detail: generator });
    }
    if (robots) {
      findings.push({ severity: "info", title: "Robots meta", detail: robots });
    }

    // 3) Assets inventory
    const scripts = src.scripts;
    const styles = [...document.querySelectorAll('link[rel~="stylesheet"]')].map((l) => l.href);
    const images = [...document.images].map((i) => i.currentSrc || i.src).filter(Boolean);
    const externalDomains = uniq([
      ...scripts.external.map(domainOf),
      ...styles.map(domainOf),
      ...images.map(domainOf)
    ].filter((d) => d && d !== location.hostname));

    timeline.push({
      id: "assets",
      state: "ok",
      detail: `${scripts.total} scripts (${scripts.external.length} external), ${styles.length} styles, ${externalDomains.length} 3rd-party domains`
    });
    findings.push({
      severity: "info",
      title: "Public asset inventory",
      detail: `Scripts: ${scripts.total} total / ${scripts.inlineCount} inline / ${scripts.external.length} external. Stylesheets: ${styles.length}. Third-party domains: ${externalDomains.length}.`,
      evidence: externalDomains.slice(0, 20).join("\n") || "(none)"
    });

    // 4) Endpoints / APIs from public source
    const endpoints = findEndpoints(src.combined);
    const interesting = endpoints.filter((u) =>
      /api|firebase|firestore|supabase|cloudfunctions|graphql|auth|token|login|paypal|stripe|zoom|googleapis/i.test(u)
    );
    timeline.push({
      id: "endpoints",
      state: interesting.length ? "warn" : "ok",
      detail: `${endpoints.length} URLs found, ${interesting.length} look API/auth related`
    });
    if (interesting.length) {
      findings.push({
        severity: "medium",
        title: "Possible public API / backend endpoints referenced",
        detail: "These appeared in public HTML/JS. Review auth rules and whether keys/config are over-exposed.",
        evidence: interesting.slice(0, 25).join("\n")
      });
    } else {
      findings.push({
        severity: "low",
        title: "Few/no obvious API endpoint strings",
        detail: "No strong API/auth URL patterns were found in public source (they may be loaded dynamically)."
      });
    }

    // Firebase-specific public clues
    const firebaseClues = uniq((
      src.combined.match(/[a-z0-9-]+\.firebaseapp\.com|[a-z0-9-]+\.web\.app|firebaseio\.com|initializeApp\s*\(/gi) || []
    ));
    if (firebaseClues.length) {
      findings.push({
        severity: "info",
        title: "Firebase-related public clues",
        detail: "Firebase hosting/config patterns appear in public source. Ensure Firestore/Storage security rules are strict.",
        evidence: firebaseClues.slice(0, 15).join("\n")
      });
    }

    // 5) Secret patterns
    const secrets = findSecrets(src.combined);
    timeline.push({
      id: "secrets",
      state: secrets.some((s) => s.severity === "high") ? "bad" : secrets.length ? "warn" : "ok",
      detail: secrets.length ? `${secrets.length} potential secret pattern(s)` : "No common secret patterns detected"
    });
    secrets.forEach((s) => {
      findings.push({
        severity: s.severity,
        title: `Possible exposed secret: ${s.type}`,
        detail: "Heuristic match in public page source. Verify manually; false positives happen. Rotate if real.",
        evidence: s.sample
      });
    });

    // 6) Forms
    const forms = [...document.forms].map((f, idx) => ({
      index: idx,
      action: f.action || "(same page)",
      method: (f.method || "get").toUpperCase(),
      hasPassword: !!f.querySelector('input[type="password"]'),
      autocomplete: f.autocomplete || null
    }));
    const insecurePasswordForm = forms.find((f) => f.hasPassword && !String(f.action).startsWith("https:") && location.protocol !== "https:");
    timeline.push({
      id: "forms",
      state: insecurePasswordForm ? "bad" : forms.some((f) => f.hasPassword) ? "ok" : "ok",
      detail: `${forms.length} form(s), ${forms.filter((f) => f.hasPassword).length} with password field`
    });
    if (forms.length) {
      findings.push({
        severity: forms.some((f) => f.hasPassword) ? "info" : "low",
        title: "Public forms detected",
        detail: "Review form actions, HTTPS, and autocomplete settings.",
        evidence: forms.slice(0, 10).map((f) => `#${f.index} ${f.method} ${f.action} password=${f.hasPassword}`).join("\n")
      });
    }
    if (insecurePasswordForm) {
      findings.push({
        severity: "high",
        title: "Password form on non-HTTPS context",
        detail: "Credentials may be exposed in transit.",
        evidence: insecurePasswordForm.action
      });
    }

    // 7) Storage keys
    let localKeys = [];
    let sessionKeys = [];
    try { localKeys = Object.keys(localStorage); } catch {}
    try { sessionKeys = Object.keys(sessionStorage); } catch {}
    timeline.push({
      id: "storage",
      state: "ok",
      detail: `localStorage keys: ${localKeys.length}, sessionStorage keys: ${sessionKeys.length}`
    });
    if (localKeys.length || sessionKeys.length) {
      findings.push({
        severity: "info",
        title: "Browser storage keys (names only)",
        detail: "Values are not dumped. Check that tokens in storage are httpOnly/secure where possible (prefer cookies for secrets).",
        evidence: `localStorage: ${localKeys.slice(0, 30).join(", ") || "(none)"}\nsessionStorage: ${sessionKeys.slice(0, 30).join(", ") || "(none)"}`
      });
    }

    // 8) Mixed content
    const activeMixed = [];
    if (isHttps) {
      [...scripts.external, ...styles, ...images].forEach((u) => {
        if (typeof u === "string" && u.startsWith("http://")) activeMixed.push(u);
      });
    }
    timeline.push({
      id: "mixed",
      state: activeMixed.length ? "bad" : "ok",
      detail: activeMixed.length ? `${activeMixed.length} http:// asset(s) on https page` : "No active mixed-content assets detected"
    });
    if (activeMixed.length) {
      findings.push({
        severity: "high",
        title: "Mixed content assets",
        detail: "HTTPS page loads HTTP resources. Browsers may block or warn; MITM risk.",
        evidence: uniq(activeMixed).slice(0, 20).join("\n")
      });
    }

    // 9) Summary status
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    let status = "Healthy";
    let state = "ok";
    if (counts.high > 0) { status = "Issues found"; state = "bad"; }
    else if (counts.medium > 0) { status = "Review recommended"; state = "warn"; }

    timeline.push({
      id: "summary",
      state,
      detail: `${status} · high=${counts.high} medium=${counts.medium} low=${counts.low} info=${counts.info}`
    });

    // Sort findings high → info
    const order = { high: 0, medium: 1, low: 2, info: 3 };
    findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

    return {
      ok: true,
      timeline,
      report: {
        tool: "web-public-security-scanner",
        version: "1.0.0",
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
          endpointsFound: endpoints.length,
          interestingEndpoints: interesting.length,
          forms: forms.length
        },
        endpoints: interesting.slice(0, 50),
        findings
      }
    };
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type !== "RUN_PUBLIC_SECURITY_SCAN") return;
    runScan()
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err?.message || String(err) }));
    return true; // async
  });
})();
