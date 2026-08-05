(() => {
  // Prevent double-defining helpers if reinjected
  if (globalThis.__publicSecurityScannerV131) {
    return;
  }
  globalThis.__publicSecurityScannerV131 = true;

  const SECRET_PATTERNS = [
    { name: "Google API key", re: /AIza[0-9A-Za-z\-_]{20,}/g, severity: "high" },
    { name: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/g, severity: "high" },
    { name: "JWT-like token", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: "medium" },
    { name: "Firebase/apiKey assignment", re: /apiKey\s*[:=]\s*['"][^'"]+['"]/gi, severity: "medium" },
    { name: "Private key PEM", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "high" },
    { name: "Slack token-like", re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: "high" },
    { name: "GitHub PAT-like", re: /gh[pousr]_[A-Za-z0-9_]{20,}/g, severity: "high" },
    { name: "Stripe live secret", re: /sk_live_[0-9a-zA-Z]{16,}/g, severity: "high" },
    { name: "Stripe publishable", re: /pk_(live|test)_[0-9a-zA-Z]{16,}/g, severity: "low" },
    { name: "OpenAI-like key", re: /sk-[A-Za-z0-9]{20,}/g, severity: "high" },
    { name: "Hardcoded password assign", re: /password\s*[:=]\s*['"][^'"]{4,}['"]/gi, severity: "medium" },
    { name: "Bearer token assign", re: /bearer\s+[A-Za-z0-9\-_.=]{20,}/gi, severity: "medium" }
  ];

  const ENDPOINT_REGEXES = [
    /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?\/[\w\-./?%&=+#]*/g,
    /['"`](\/api\/[\w\-./?%&=]*)['"`]/g,
    /['"`](\/v[0-9]+\/[\w\-./?%&=]*)['"`]/g,
    /firebaseio\.com|firestore\.googleapis\.com|identitytoolkit\.googleapis\.com|securetoken\.googleapis\.com|cloudfunctions\.net|supabase\.co|amazonaws\.com|firebasestorage\.googleapis\.com/gi
  ];

  const PDF_LINK_RE =
    /https?:\/\/[^\s'"<>]+?\.pdf(?:\?[^\s'"<>]*)?|blob:https?:\/\/[^\s'"<>]+|https?:\/\/firebasestorage\.googleapis\.com\/[^\s'"<>]+|https?:\/\/storage\.googleapis\.com\/[^\s'"<>]+/gi;

  const LIB_PATTERNS = [
    { name: "jQuery", re: /jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)/i },
    { name: "AngularJS", re: /angular[.-]([0-9]+\.[0-9]+\.[0-9]+)/i },
    { name: "React", re: /react(?:\.production)?(?:\.min)?\.js/i },
    { name: "Vue", re: /vue(?:\.runtime)?(?:\.min)?\.js/i },
    { name: "Lodash", re: /lodash(?:\.min)?\.js/i },
    { name: "Bootstrap", re: /bootstrap(?:\.bundle)?(?:\.min)?\.js/i },
    { name: "Firebase", re: /firebase-(?:app|auth|firestore|storage)/i },
    { name: "Moment", re: /moment(?:\.min)?\.js/i }
  ];

  const XSS_SINK_RES = [
    { name: "innerHTML", re: /\.innerHTML\s*=/g },
    { name: "outerHTML", re: /\.outerHTML\s*=/g },
    { name: "document.write", re: /document\.write\s*\(/g },
    { name: "insertAdjacentHTML", re: /insertAdjacentHTML\s*\(/g },
    { name: "jquery.html", re: /\$\([^)]*\)\.html\s*\(/g }
  ];

  const DANGEROUS_JS_RES = [
    { name: "eval(", re: /\beval\s*\(/g, severity: "high" },
    { name: "new Function(", re: /new\s+Function\s*\(/g, severity: "high" },
    { name: "setTimeout(string)", re: /setTimeout\s*\(\s*['"]/g, severity: "medium" },
    { name: "setInterval(string)", re: /setInterval\s*\(\s*['"]/g, severity: "medium" },
    { name: "document.domain", re: /document\.domain\s*=/g, severity: "medium" },
    { name: "postMessage * origin", re: /postMessage\s*\([^,]+,\s*['"]\*['"]/g, severity: "medium" }
  ];

  const ADMIN_PATH_RE =
    /['"`](\/(?:admin|administrator|dashboard|debug|phpinfo|server-status|\.env|wp-admin|graphql|swagger|api-docs)[^'"`]*)['"`]/gi;
  const SOURCEMAP_RE = /\/\/# sourceMappingURL=([^\s]+)|\.js\.map/gi;
  const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const DEBUG_RE = /\b(debug\s*[:=]\s*true|NODE_ENV\s*[:=]\s*['"]development['"]|__DEV__\s*[:=]\s*true)/gi;

  function uniq(a) {
    return [...new Set((a || []).filter(Boolean))];
  }
  function clip(s, n) {
    n = n || 180;
    s = String(s || "");
    return s.length > n ? s.slice(0, n) + "…" : s;
  }
  function domainOf(url) {
    try {
      return new URL(url, location.href).hostname;
    } catch (e) {
      return null;
    }
  }
  function countMatches(text, re) {
    try {
      const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
      const r = new RegExp(re.source, flags);
      return (String(text || "").match(r) || []).length;
    } catch (e) {
      return 0;
    }
  }

  function getScripts() {
    const scripts = Array.from(document.scripts || []);
    return {
      total: scripts.length,
      external: scripts.filter((s) => s.src).map((s) => s.src),
      inlineCount: scripts.filter((s) => !s.src).length,
      inlineText: scripts
        .filter((s) => !s.src)
        .map((s) => s.textContent || "")
        .join("\n")
    };
  }

  function collectSource() {
    let html = "";
    try {
      html = document.documentElement ? document.documentElement.outerHTML : "";
    } catch (e) {
      html = document.body ? document.body.innerHTML : "";
    }
    // Cap huge pages to avoid OOM/timeouts
    if (html.length > 1500000) html = html.slice(0, 1500000);
    const scripts = getScripts();
    const inline = (scripts.inlineText || "").slice(0, 400000);
    return { html, scripts, combined: html + "\n" + inline };
  }

  function findEndpoints(text) {
    const found = [];
    for (const re of ENDPOINT_REGEXES) {
      try {
        const copy = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
        let m;
        while ((m = copy.exec(text)) !== null) found.push(m[1] || m[0]);
      } catch (e) {}
    }
    return uniq(found).slice(0, 120);
  }

  function findSecrets(text) {
    const hits = [];
    for (const p of SECRET_PATTERNS) {
      try {
        const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
        uniq(text.match(re) || [])
          .slice(0, 5)
          .forEach((val) => hits.push({ type: p.name, severity: p.severity, sample: clip(val, 56) }));
      } catch (e) {}
    }
    return hits;
  }

  function decodeJwtPayload(token) {
    try {
      const part = token.split(".")[1];
      const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(atob(b64));
    } catch (e) {
      return null;
    }
  }

  function analyzeStorage() {
    const localEntries = [];
    const sessionEntries = [];
    const jwtHits = [];
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        const v = localStorage.getItem(k) || "";
        localEntries.push({ key: k, valuePreview: clip(v, 100), len: v.length });
        const jwts = v.match(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g) || [];
        jwts.forEach((t) =>
          jwtHits.push({ where: "localStorage:" + k, token: clip(t, 40), payload: decodeJwtPayload(t) })
        );
      }
    } catch (e) {}
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        const v = sessionStorage.getItem(k) || "";
        sessionEntries.push({ key: k, valuePreview: clip(v, 100), len: v.length });
        const jwts = v.match(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g) || [];
        jwts.forEach((t) =>
          jwtHits.push({ where: "sessionStorage:" + k, token: clip(t, 40), payload: decodeJwtPayload(t) })
        );
      }
    } catch (e) {}

    const vipKeys = localEntries.filter((e) => /vip|premium|pro\b|subscri|plan|entitlement|was_vip|isVip|is_vip/i.test(e.key));
    const authKeys = localEntries.filter((e) =>
      /token|auth|session|uid|user|jwt|firebase:authUser|idToken|refresh/i.test(e.key)
    );
    const deviceKeys = localEntries.filter((e) => /device|fingerprint|install/i.test(e.key));
    const vipFlags = vipKeys.map((e) => {
      let parsed;
      try {
        parsed = JSON.parse(localStorage.getItem(e.key));
      } catch (err) {
        parsed = localStorage.getItem(e.key);
      }
      const truthy = parsed === true || parsed === "true" || parsed === 1 || parsed === "1";
      return { key: e.key, value: String(parsed), truthy };
    });
    const firebaseAuthHint = /firestore_zombie|firebase:authUser|firebase/i.test(
      localEntries.map((e) => e.key).join(" ")
    );
    return { localEntries, sessionEntries, jwtHits, vipKeys, authKeys, deviceKeys, vipFlags, firebaseAuthHint };
  }

  function analyzeAccount(storage, bodyText) {
    const signedInUi = /تسجيل الخروج|sign\s*out|log\s*out|حسابي|my account|profile/i.test(bodyText);
    const loginUi = /تسجيل الدخول|sign\s*in|log\s*in|google/i.test(bodyText);
    const vipFalse = storage.vipFlags.some((v) => !v.truthy);
    const vipTrue = storage.vipFlags.some((v) => v.truthy);
    let status = "unknown";
    if (vipTrue) status = "vip_flag_true_client";
    else if (storage.vipFlags.length && vipFalse) status = "logged_in_non_vip_likely";
    else if (storage.authKeys.length || storage.firebaseAuthHint) status = "auth_signals_present";
    else if (signedInUi) status = "signed_in_ui";
    else if (loginUi) status = "login_ui_visible";
    return { status, signedInUi, loginUi, vipFalse, vipTrue };
  }

  function analyzePaywall(text, bodyText) {
    const patterns = [
      /\bVIP\b/i,
      /premium/i,
      /subscribe|subscription|اشتراك/i,
      /paywall|locked|مقفل|🔒/i,
      /paypal|stripe|cib|ccp|بريدي/i,
      /compte vip|حساب\s*vip|يلزم.*vip|vip account/i
    ];
    const hits = patterns.filter((re) => re.test(bodyText) || re.test(text)).map(String);
    const lockButtons = Array.from(document.querySelectorAll("button, a, [role=button]"))
      .map((el) => (el.innerText || el.textContent || "").trim())
      .filter((t) => t && /vip|premium|subscribe|اشتراك|مقفل|🔒|pro|الحل النموذجي/i.test(t))
      .slice(0, 25);
    return { hits, lockButtons, likelyPaywall: hits.length >= 1 || lockButtons.length > 0 };
  }

  function findPdfLinks(text) {
    const fromText = text.match(PDF_LINK_RE) || [];
    const fromAnchors = Array.from(document.querySelectorAll("a[href]"))
      .map((a) => a.href)
      .filter((h) => /\.pdf($|\?)|firebasestorage|storage\.googleapis|blob:/i.test(h));
    const fromEmbeds = Array.from(document.querySelectorAll("embed[src], iframe[src], object[data]"))
      .map((el) => el.src || el.data)
      .filter((h) => h && /\.pdf|blob:|storage/i.test(h));
    const pdfButtons = Array.from(document.querySelectorAll("button, a, [role=button]"))
      .map((el) => (el.innerText || "").trim())
      .filter((t) => /pdf|طباعة|print|تحميل|download|ورقة الامتحان|ملف/i.test(t))
      .slice(0, 20);
    const usesPrint = /window\.print\s*\(|print\s*\(/i.test(text);
    return {
      links: uniq(fromText.concat(fromAnchors, fromEmbeds)).slice(0, 40),
      pdfButtons,
      usesPrint
    };
  }

  function analyzeLinks() {
    const anchors = Array.from(document.querySelectorAll("a[href]"));
    const blankNoopener = [];
    const jsLinks = [];
    const external = [];
    const openRedirectish = [];
    anchors.forEach((a) => {
      const href = a.getAttribute("href") || "";
      if (/^javascript:/i.test(href)) jsLinks.push(href);
      if (a.target === "_blank") {
        const rel = (a.getAttribute("rel") || "").toLowerCase();
        if (!rel.includes("noopener") && !rel.includes("noreferrer")) blankNoopener.push(a.href || href);
      }
      try {
        const u = new URL(a.href, location.href);
        if (u.hostname && u.hostname !== location.hostname) external.push(u.hostname);
        ["next", "redirect", "url", "return", "returnUrl", "continue", "dest"].forEach((p) => {
          const v = u.searchParams.get(p);
          if (v && /^https?:/i.test(v)) openRedirectish.push(p + "=" + clip(v, 60));
        });
      } catch (e) {}
    });
    return {
      total: anchors.length,
      blankNoopener: uniq(blankNoopener).slice(0, 15),
      jsLinks: uniq(jsLinks).slice(0, 10),
      externalHosts: uniq(external).slice(0, 20),
      openRedirectish: uniq(openRedirectish).slice(0, 15)
    };
  }

  function sniffLibraries(scriptUrls, text) {
    const found = [];
    const hay = scriptUrls.join("\n") + "\n" + String(text || "").slice(0, 200000);
    LIB_PATTERNS.forEach((lib) => {
      const m = hay.match(lib.re);
      if (m) found.push({ name: lib.name, evidence: clip(m[0], 80), version: m[1] || null });
    });
    return found;
  }

  function urlParamSecrets() {
    const out = [];
    try {
      const u = new URL(location.href);
      u.searchParams.forEach((val, key) => {
        if (/token|key|auth|session|password|secret|id_token|access/i.test(key) || /eyJ[A-Za-z0-9_-]+\./.test(val)) {
          out.push(key + "=" + clip(val, 40));
        }
      });
    } catch (e) {}
    return out;
  }

  async function runScan() {
    const timeline = [];
    const findings = [];
    const startedAt = new Date().toISOString();
    const src = collectSource();
    const bodyText = ((document.body && document.body.innerText) || "").slice(0, 25000);
    const text = src.combined || "";

    // 1 HTTPS
    const isHttps = location.protocol === "https:";
    timeline.push({ id: "https", state: isHttps ? "ok" : "bad", detail: isHttps ? "HTTPS OK" : "Not HTTPS" });
    findings.push(
      isHttps
        ? { severity: "info", title: "HTTPS مفعّل", detail: "الاتصال مشفّر.", evidence: location.origin }
        : { severity: "high", title: "الموقع ليس HTTPS", detail: "البيانات قد تُعترض.", evidence: location.href }
    );

    // 2 meta
    let cspMeta = null;
    let xfoMeta = null;
    let generator = null;
    let robots = null;
    try {
      cspMeta =
        (document.querySelector('meta[http-equiv="Content-Security-Policy" i]') ||
          document.querySelector('meta[http-equiv="Content-Security-Policy"]') ||
          {}
        ).content || null;
      xfoMeta =
        (document.querySelector('meta[http-equiv="X-Frame-Options" i]') ||
          document.querySelector('meta[http-equiv="X-Frame-Options"]') ||
          {}
        ).content || null;
      generator = (document.querySelector('meta[name="generator" i]') || document.querySelector('meta[name="generator"]') || {}).content || null;
      robots = (document.querySelector('meta[name="robots" i]') || document.querySelector('meta[name="robots"]') || {}).content || null;
    } catch (e) {}
    timeline.push({ id: "meta", state: cspMeta ? "ok" : "warn", detail: cspMeta ? "CSP meta موجود" : "لا CSP meta" });
    if (!cspMeta)
      findings.push({
        severity: "low",
        title: "لا Content-Security-Policy meta",
        detail: "تحقق من Response Headers. يقلل XSS."
      });
    else findings.push({ severity: "info", title: "CSP meta موجود", detail: clip(cspMeta, 200) });
    if (!xfoMeta)
      findings.push({
        severity: "low",
        title: "لا X-Frame-Options meta",
        detail: "قد توجد حماية framing في الهيدر. بدونها خطر clickjacking محتمل."
      });
    if (generator) findings.push({ severity: "info", title: "Generator", detail: generator });
    if (robots) findings.push({ severity: "info", title: "Robots meta", detail: robots });

    // 3 assets + SW
    const scripts = src.scripts;
    const styles = Array.from(document.querySelectorAll('link[rel~="stylesheet"]')).map((l) => l.href);
    const images = Array.from(document.images || [])
      .map((i) => i.currentSrc || i.src)
      .filter(Boolean);
    const externalDomains = uniq(
      scripts.external
        .concat(styles, images)
        .map(domainOf)
        .filter((d) => d && d !== location.hostname)
    );
    let swCount = 0;
    try {
      if (navigator.serviceWorker) swCount = (await navigator.serviceWorker.getRegistrations()).length;
    } catch (e) {}
    timeline.push({
      id: "assets",
      state: "ok",
      detail: "scripts=" + scripts.total + ", 3rd=" + externalDomains.length + ", SW=" + swCount
    });
    findings.push({
      severity: "info",
      title: "جرد الأصول العامة",
      detail:
        "Scripts " +
        scripts.total +
        " (inline " +
        scripts.inlineCount +
        "/ext " +
        scripts.external.length +
        "). CSS " +
        styles.length +
        ". 3rd " +
        externalDomains.length +
        ". SW " +
        swCount +
        ".",
      evidence: externalDomains.slice(0, 20).join("\n") || "(none)"
    });
    if (swCount > 0)
      findings.push({
        severity: "info",
        title: "Service Worker مسجّل",
        detail: "قد يخفي التحميلات. عطّل cache عند الاختبار."
      });

    // 4 libs
    const libs = sniffLibraries(scripts.external, text);
    timeline.push({ id: "libs", state: "ok", detail: libs.length + " lib signal(s)" });
    if (libs.length)
      findings.push({
        severity: "info",
        title: "مكتبات JS مكتشفة",
        detail: "إشارات أسماء فقط — ليس CVE كامل.",
        evidence: libs.map((l) => l.name + (l.version ? "@" + l.version : "")).join(", ")
      });

    // 5 endpoints
    const endpoints = findEndpoints(text);
    const interesting = endpoints.filter(
      (u) =>
        /api|firebase|firestore|supabase|cloudfunctions|graphql|auth|token|login|paypal|stripe|googleapis|webchannel|gsessionid/i.test(
          u
        ) && !/fonts\.googleapis|fonts\.gstatic|woff2?/i.test(u)
    );
    timeline.push({
      id: "endpoints",
      state: interesting.length ? "warn" : "ok",
      detail: interesting.length + " api-like"
    });
    if (interesting.length)
      findings.push({
        severity: "medium",
        title: "روابط API/Backend محتملة",
        detail: "راجع قواعد الحماية. قد تشمل Google Auth iframe.",
        evidence: interesting.slice(0, 25).join("\n")
      });
    else
      findings.push({
        severity: "low",
        title: "لا API واضح في السورس",
        detail: "قد تُحمَّل ديناميكيًا عبر Firestore."
      });

    // 6 firebase
    const fbClues = uniq(
      text.match(
        /[a-z0-9-]+\.firebaseapp\.com|[a-z0-9-]+\.web\.app|initializeApp\s*\(|firebase-(?:app|auth|firestore|storage)|firebasestorage|identitytoolkit/gi
      ) || []
    );
    let storageProject = [];
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i) || "";
        const m = k.match(/firestore_zombie_firestore\/\[DEFAULT\]\/([a-z0-9-]+)/i);
        if (m) storageProject.push(m[1]);
      }
    } catch (e) {}
    storageProject = uniq(storageProject);
    const onFbHost = /\.web\.app$|\.firebaseapp\.com$/i.test(location.hostname);
    timeline.push({
      id: "firebase",
      state: fbClues.length || onFbHost || storageProject.length ? "warn" : "ok",
      detail: storageProject[0] ? "project≈" + storageProject[0] : fbClues.length + " clues"
    });
    if (onFbHost || fbClues.length || storageProject.length) {
      findings.push({
        severity: "info",
        title: "مؤشرات Firebase",
        detail: "apiKey/projectId العامة طبيعية. الحماية = Rules + Auth.",
        evidence: ["host=" + location.hostname]
          .concat(storageProject.length ? ["projectId≈" + storageProject.join(",")] : [], fbClues.slice(0, 12))
          .join("\n")
      });
    }

    // 7 secrets
    const secrets = findSecrets(text);
    const urlSecrets = urlParamSecrets();
    secrets.forEach((s) => {
      let sev = s.severity;
      let detail = "Heuristic — قد يكون إيجابي كاذب.";
      if (s.type === "Google API key") {
        sev = "low";
        detail = "مفتاح Google/Firebase العام شائع. ليس Admin SDK. الحماية في Rules.";
      }
      findings.push({ severity: sev, title: "نمط سر محتمل: " + s.type, detail: detail, evidence: s.sample });
    });
    if (urlSecrets.length)
      findings.push({
        severity: "high",
        title: "أسرار في رابط الصفحة",
        detail: "لا تضع tokens في query string.",
        evidence: urlSecrets.join("\n")
      });
    timeline.push({
      id: "secrets",
      state: secrets.some((s) => s.severity === "high") || urlSecrets.length ? "bad" : secrets.length ? "warn" : "ok",
      detail: secrets.length + " hits"
    });

    // 8 pdf
    const pdf = findPdfLinks(text);
    const publicPdf = pdf.links.filter((u) => /^https?:/i.test(u) && u.indexOf("blob:") !== 0);
    const blobPdf = pdf.links.filter((u) => u.indexOf("blob:") === 0);
    timeline.push({
      id: "pdf",
      state: publicPdf.length ? "warn" : "ok",
      detail: publicPdf.length ? publicPdf.length + " public pdf urls" : "no direct pdf url"
    });
    if (publicPdf.length)
      findings.push({
        severity: "medium",
        title: "روابط PDF/Storage عامة",
        detail: "اختبر Incognito. المدفوع يحتاج signed URL + rules.",
        evidence: publicPdf.slice(0, 15).join("\n")
      });
    else
      findings.push({
        severity: "info",
        title: "لا رابط PDF مباشر في السورس",
        detail: "غالبًا Print-to-PDF أو blob بعد الضغط."
      });
    if (blobPdf.length)
      findings.push({
        severity: "low",
        title: "روابط blob",
        detail: "ملفات مؤقتة بالمتصفح.",
        evidence: blobPdf.slice(0, 8).join("\n")
      });
    if (pdf.usesPrint)
      findings.push({ severity: "info", title: "window.print موجود", detail: "التحميل عبر طباعة/حفظ PDF." });
    if (pdf.pdfButtons.length)
      findings.push({
        severity: "info",
        title: "أزرار PDF/تحميل/طباعة",
        detail: "راقب Network عند الضغط.",
        evidence: pdf.pdfButtons.slice(0, 12).join(" | ")
      });

    // 9 account
    const storage = analyzeStorage();
    const account = analyzeAccount(storage, bodyText);
    timeline.push({ id: "account", state: storage.vipFlags.length ? "warn" : "ok", detail: account.status });
    findings.push({
      severity: "info",
      title: "إشارات الحساب / التخزين",
      detail:
        "status=" +
        account.status +
        ". VIP flags=" +
        storage.vipFlags.length +
        ". authKeys=" +
        storage.authKeys.length +
        ".",
      evidence:
        storage.localEntries
          .slice(0, 20)
          .map((e) => e.key + " = " + e.valuePreview)
          .join("\n") || "(empty)"
    });
    if (storage.vipFlags.length) {
      const anyTrue = storage.vipFlags.some((v) => v.truthy);
      findings.push({
        severity: "medium",
        title: "أعلام VIP في localStorage",
        detail: anyTrue
          ? "VIP=true على العميل — تأكد من فرض السيرفر."
          : "VIP=false (مقفل). UI جيد؛ server-side مطلوب.",
        evidence: storage.vipFlags.map((v) => v.key + "=" + v.value).join("\n")
      });
    }
    if (storage.authKeys.length)
      findings.push({
        severity: "low",
        title: "مفاتيح auth في التخزين",
        detail: "عرضة لـ XSS.",
        evidence: storage.authKeys.map((e) => e.key).join(", ")
      });
    if (account.status === "logged_in_non_vip_likely")
      findings.push({
        severity: "info",
        title: "حساب مسجّل وغير VIP غالبًا",
        detail: "متوافق مع قفل الحلول."
      });

    // 10 jwt
    timeline.push({ id: "jwt", state: storage.jwtHits.length ? "warn" : "ok", detail: storage.jwtHits.length + " jwt" });
    if (storage.jwtHits.length)
      findings.push({
        severity: "medium",
        title: "JWT في التخزين",
        detail: "افحص الانتهاء/الخوارزمية.",
        evidence: storage.jwtHits
          .slice(0, 8)
          .map((j) => j.where + " :: " + j.token)
          .join("\n")
      });
    else
      findings.push({
        severity: "info",
        title: "لا JWT واضح في storage",
        detail: "قد تكون الجلسة في IndexedDB/httpOnly."
      });

    // 11 forms
    const forms = Array.from(document.forms || []).map((f, idx) => ({
      index: idx,
      action: f.action || "(same)",
      method: (f.method || "get").toUpperCase(),
      hasPassword: !!f.querySelector('input[type="password"]')
    }));
    const badPass = forms.find((f) => f.hasPassword && location.protocol !== "https:");
    timeline.push({ id: "forms", state: badPass ? "bad" : "ok", detail: forms.length + " forms" });
    if (forms.length)
      findings.push({
        severity: "info",
        title: "نماذج Forms",
        detail: "راجع action/HTTPS.",
        evidence: forms
          .slice(0, 10)
          .map((f) => "#" + f.index + " " + f.method + " " + f.action + " pass=" + f.hasPassword)
          .join("\n")
      });
    if (badPass) findings.push({ severity: "high", title: "كلمة مرور على غير HTTPS", detail: "خطر اعتراض." });
    const pwdInputs = Array.from(document.querySelectorAll('input[type="password"]'));
    if (pwdInputs.length)
      findings.push({ severity: "low", title: "حقول كلمة المرور", detail: pwdInputs.length + " password input(s)." });

    // 12 links
    const links = analyzeLinks();
    timeline.push({
      id: "links",
      state: links.blankNoopener.length || links.jsLinks.length || links.openRedirectish.length ? "warn" : "ok",
      detail: "blankNoRel=" + links.blankNoopener.length
    });
    if (links.blankNoopener.length)
      findings.push({
        severity: "low",
        title: "target=_blank بدون noopener",
        detail: "أضف rel=noopener noreferrer.",
        evidence: links.blankNoopener.slice(0, 10).join("\n")
      });
    if (links.jsLinks.length)
      findings.push({
        severity: "low",
        title: "روابط javascript:",
        detail: "تجنّبها.",
        evidence: links.jsLinks.join("\n")
      });
    if (links.openRedirectish.length)
      findings.push({
        severity: "medium",
        title: "معلمات redirect/url خارجية في الروابط",
        detail: "تحقق من حماية Open Redirect على السيرفر.",
        evidence: links.openRedirectish.join("\n")
      });

    // 13 XSS sinks
    const xssHits = XSS_SINK_RES.map((s) => ({ name: s.name, count: countMatches(text, s.re) })).filter(
      (x) => x.count > 0
    );
    timeline.push({
      id: "xss",
      state: xssHits.length ? "warn" : "ok",
      detail: xssHits.length ? xssHits.map((x) => x.name + ":" + x.count).join(", ") : "no common sinks"
    });
    if (xssHits.length)
      findings.push({
        severity: "medium",
        title: "DOM XSS sinks في السورس",
        detail: "وجود sink لا يعني ثغرة مؤكدة.",
        evidence: xssHits.map((x) => x.name + " x " + x.count).join("\n")
      });
    else
      findings.push({
        severity: "info",
        title: "لا sinks DOM XSS شائعة ظاهرة",
        detail: "قد تكون في ملفات JS الخارجية."
      });

    // 14 dangerous js
    const dang = DANGEROUS_JS_RES.map((s) => Object.assign({}, s, { count: countMatches(text, s.re) })).filter(
      (x) => x.count > 0
    );
    timeline.push({
      id: "dangerousjs",
      state: dang.some((d) => d.severity === "high") ? "bad" : dang.length ? "warn" : "ok",
      detail: dang.length ? dang.map((d) => d.name).join(", ") : "clean"
    });
    dang.forEach((d) =>
      findings.push({
        severity: d.severity,
        title: "JS خطر: " + d.name,
        detail: "ظهر " + d.count + " مرة في السورس/الـ inline.",
        evidence: d.name
      })
    );

    // 15 admin paths
    let adminPaths = [];
    try {
      adminPaths = uniq((text.match(ADMIN_PATH_RE) || []).map((m) => m.replace(/['"`]/g, ""))).slice(0, 20);
    } catch (e) {}
    const debugHits = countMatches(text, DEBUG_RE);
    timeline.push({
      id: "admin",
      state: adminPaths.length ? "warn" : "ok",
      detail: adminPaths.length + " path-like, debug=" + debugHits
    });
    if (adminPaths.length)
      findings.push({
        severity: "medium",
        title: "مسارات admin/debug في السورس",
        detail: "تحقق أنها محمية.",
        evidence: adminPaths.join("\n")
      });
    if (debugHits > 5)
      findings.push({
        severity: "low",
        title: "إشارات debug كثيرة",
        detail: debugHits + " إشارات."
      });

    // 16 sourcemaps
    let maps = [];
    try {
      maps = uniq(text.match(SOURCEMAP_RE) || []).slice(0, 15);
    } catch (e) {}
    timeline.push({ id: "sourcemap", state: maps.length ? "warn" : "ok", detail: maps.length + " sourcemap hints" });
    if (maps.length)
      findings.push({
        severity: "low",
        title: "Source maps محتملة",
        detail: "قد تكشف الكود الأصلي إن كانت عامة.",
        evidence: maps.join("\n")
      });

    // 17 PII
    let emails = [];
    try {
      emails = uniq(bodyText.match(EMAIL_RE) || [])
        .filter((e) => !/example\.com|sentry|w3\.org|schema\.org/i.test(e))
        .slice(0, 15);
    } catch (e) {}
    timeline.push({ id: "pii", state: emails.length ? "warn" : "ok", detail: "emails=" + emails.length });
    if (emails.length)
      findings.push({
        severity: "low",
        title: "بريد ظاهر في الصفحة",
        detail: "تأكد أنه مقصود للعامة.",
        evidence: emails.join("\n")
      });

    // 18 iframes
    const iframes = Array.from(document.querySelectorAll("iframe")).map((f) => ({
      src: f.src || f.getAttribute("src") || "(empty)",
      sandbox: f.getAttribute("sandbox")
    }));
    timeline.push({ id: "iframes", state: "ok", detail: iframes.length + " iframe(s)" });
    if (iframes.length) {
      findings.push({
        severity: "info",
        title: "Iframes موجودة",
        detail: iframes.length + " iframe(s).",
        evidence: iframes
          .slice(0, 10)
          .map((f) => f.src)
          .join("\n")
      });
      const noSandbox = iframes.filter((f) => !f.sandbox && f.src && !/google|firebase|youtube|vimeo/i.test(f.src));
      if (noSandbox.length)
        findings.push({
          severity: "low",
          title: "iframe بدون sandbox",
          detail: "راجع مصادر الطرف الثالث.",
          evidence: noSandbox
            .map((f) => f.src)
            .slice(0, 8)
            .join("\n")
        });
    }

    // 19 cookies
    const cookieNames = (document.cookie || "")
      .split(";")
      .map((x) => x.trim().split("=")[0])
      .filter(Boolean);
    timeline.push({ id: "cookies", state: "ok", detail: cookieNames.length + " visible" });
    findings.push({
      severity: "info",
      title: "كوكيز ظاهرة لـ JS",
      detail: "httpOnly لا تظهر (جيد للأسرار).",
      evidence: cookieNames.join(", ") || "(none)"
    });

    // 20 paywall
    const paywall = analyzePaywall(text, bodyText);
    timeline.push({ id: "paywall", state: "ok", detail: paywall.likelyPaywall ? "yes" : "no" });
    if (paywall.likelyPaywall)
      findings.push({
        severity: "info",
        title: "إشارات Paywall/VIP",
        detail: "ادمج مع VIP flags + رفض السيرفر.",
        evidence:
          "buttons: " +
          (paywall.lockButtons.slice(0, 12).join(" | ") || "(none)") +
          "\npatterns: " +
          paywall.hits.length
      });

    // 21 mixed
    const mixed = [];
    if (isHttps) {
      scripts.external.concat(styles, images).forEach((u) => {
        if (String(u).indexOf("http://") === 0) mixed.push(u);
      });
    }
    timeline.push({ id: "mixed", state: mixed.length ? "bad" : "ok", detail: mixed.length ? String(mixed.length) : "none" });
    if (mixed.length)
      findings.push({
        severity: "high",
        title: "Mixed content",
        detail: "HTTPS يحمّل HTTP.",
        evidence: uniq(mixed).slice(0, 15).join("\n")
      });

    // 22 summary
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    let status = "Healthy";
    let state = "ok";
    if (counts.high > 0) {
      status = "Issues found";
      state = "bad";
    } else if (counts.medium > 0) {
      status = "Review recommended";
      state = "warn";
    }
    timeline.push({
      id: "summary",
      state: state,
      detail: status + " · H" + counts.high + " M" + counts.medium + " L" + counts.low + " I" + counts.info
    });

    const order = { high: 0, medium: 1, low: 2, info: 3 };
    findings.sort((a, b) => (order[a.severity] != null ? order[a.severity] : 9) - (order[b.severity] != null ? order[b.severity] : 9));

    return {
      ok: true,
      timeline: timeline,
      report: {
        tool: "web-public-security-scanner",
        version: "1.3.1",
        startedAt: startedAt,
        finishedAt: new Date().toISOString(),
        url: location.href,
        origin: location.origin,
        status: status,
        counts: counts,
        accountStatus: account.status,
        firebaseProjectHints: storageProject,
        inventory: {
          scriptsTotal: scripts.total,
          thirdPartyDomains: externalDomains,
          serviceWorkers: swCount,
          libraries: libs,
          pdfLinks: pdf.links.length,
          vipFlags: storage.vipFlags,
          xssSinks: xssHits,
          dangerousJs: dang.map((d) => d.name)
        },
        findings: findings
      }
    };
  }

  // Expose for popup executeScript call (reliable)
  globalThis.__runPublicSecurityScan = runScan;
})();
