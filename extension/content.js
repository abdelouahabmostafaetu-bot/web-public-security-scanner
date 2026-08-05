(() => {
  window.__publicSecurityScannerLoaded = true;

  const SECRET_PATTERNS = [
    { name: "Google API key", re: /AIza[0-9A-Za-z\-_]{20,}/g, severity: "high" },
    { name: "AWS Access Key ID", re: /AKIA[0-9A-Z]{16}/g, severity: "high" },
    { name: "JWT-like token", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: "medium" },
    { name: "Firebase/apiKey assignment", re: /apiKey\s*[:=]\s*[\"'][^\"']+[\"']/gi, severity: "medium" },
    { name: "Private key PEM", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "high" },
    { name: "Slack token-like", re: /xox[baprs]-[0-9A-Za-z-]{10,}/g, severity: "high" },
    { name: "GitHub PAT-like", re: /gh[pousr]_[A-Za-z0-9_]{20,}/g, severity: "high" },
    { name: "Stripe live secret", re: /sk_live_[0-9a-zA-Z]{16,}/g, severity: "high" },
    { name: "Stripe publishable", re: /pk_(live|test)_[0-9a-zA-Z]{16,}/g, severity: "low" },
    { name: "OpenAI-like key", re: /sk-[A-Za-z0-9]{20,}/g, severity: "high" },
    { name: "Hardcoded password assign", re: /password\s*[:=]\s*[\"'][^\"']{4,}[\"']/gi, severity: "medium" },
    { name: "Bearer token assign", re: /bearer\s+[A-Za-z0-9\-_.=]{20,}/gi, severity: "medium" }
  ];

  const ENDPOINT_REGEXES = [
    /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?\/[\w\-./?%&=+#]*/g,
    /[\"'`](\/api\/[\w\-./?%&=]*)[\"'`]/g,
    /[\"'`](\/v[0-9]+\/[\w\-./?%&=]*)[\"'`]/g,
    /firebaseio\.com|firestore\.googleapis\.com|identitytoolkit\.googleapis\.com|securetoken\.googleapis\.com|cloudfunctions\.net|supabase\.co|amazonaws\.com|firebasestorage\.googleapis\.com/gi
  ];

  const PDF_LINK_RE = /https?:\/\/[^\"'\s>]+?\.pdf(?:\?[^\"'\s>]*)?|blob:https?:\/\/[^\"'\s>]+|https?:\/\/firebasestorage\.googleapis\.com\/[^\"'\s>]+|https?:\/\/storage\.googleapis\.com\/[^\"'\s>]+/gi;

  // inspired by public scanners (RetireJS-style library sniffing — versions only)
  const LIB_PATTERNS = [
    { name: "jQuery", re: /jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)/i },
    { name: "AngularJS", re: /angular[.-]([0-9]+\.[0-9]+\.[0-9]+)/i },
    { name: "React", re: /react(?:\.production)?(?:\.min)?\.js/i },
    { name: "Vue", re: /vue(?:\.runtime)?(?:\.min)?\.js/i },
    { name: "Lodash", re: /lodash(?:\.min)?\.js/i },
    { name: "Bootstrap", re: /bootstrap(?:\.bundle)?(?:\.min)?\.js/i },
    { name: "Firebase", re: /firebase-(?:app|auth|firestore|storage)(?:\.js)?/i },
    { name: "Moment", re: /moment(?:\.min)?\.js/i }
  ];

  function uniq(a) { return [...new Set(a.filter(Boolean))]; }
  function clip(s, n = 180) { s = String(s || ""); return s.length > n ? s.slice(0, n) + "…" : s; }
  function domainOf(url) { try { return new URL(url, location.href).hostname; } catch { return null; } }

  function getScripts() {
    const scripts = [...document.scripts];
    return {
      total: scripts.length,
      external: scripts.filter((s) => s.src).map((s) => s.src),
      inlineCount: scripts.filter((s) => !s.src).length,
      inlineText: scripts.filter((s) => !s.src).map((s) => s.textContent || "").join("\n")
    };
  }

  function collectSource() {
    const html = document.documentElement?.outerHTML || "";
    const scripts = getScripts();
    return { html, scripts, combined: html + "\n" + scripts.inlineText };
  }

  function findEndpoints(text) {
    const found = [];
    for (const re of ENDPOINT_REGEXES) {
      const copy = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
      let m; while ((m = copy.exec(text)) !== null) found.push(m[1] || m[0]);
    }
    return uniq(found).slice(0, 120);
  }

  function findSecrets(text) {
    const hits = [];
    for (const p of SECRET_PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
      uniq(text.match(re) || []).slice(0, 5).forEach((val) => {
        hits.push({ type: p.name, severity: p.severity, sample: clip(val, 56) });
      });
    }
    return hits;
  }

  function decodeJwtPayload(token) {
    try {
      const part = token.split(".")[1];
      const json = atob(part.replace(/-/g, "+").replace(/_/g, "/"));
      return JSON.parse(json);
    } catch { return null; }
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
        jwts.forEach((t) => jwtHits.push({ where: `localStorage:${k}`, token: clip(t, 40), payload: decodeJwtPayload(t) }));
      }
    } catch {}
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        const v = sessionStorage.getItem(k) || "";
        sessionEntries.push({ key: k, valuePreview: clip(v, 100), len: v.length });
        const jwts = v.match(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g) || [];
        jwts.forEach((t) => jwtHits.push({ where: `sessionStorage:${k}`, token: clip(t, 40), payload: decodeJwtPayload(t) }));
      }
    } catch {}

    const vipKeys = localEntries.filter((e) => /vip|premium|pro\b|subscri|plan|entitlement|was_vip|isVip|is_vip/i.test(e.key));
    const authKeys = localEntries.filter((e) => /token|auth|session|uid|user|jwt|firebase:authUser|idToken|refresh/i.test(e.key));
    const deviceKeys = localEntries.filter((e) => /device|fingerprint|install/i.test(e.key));
    const cacheKeys = localEntries.filter((e) => /cache|exam|content|zombie/i.test(e.key));

    const vipFlags = vipKeys.map((e) => {
      let parsed = e.valuePreview;
      try { parsed = JSON.parse(localStorage.getItem(e.key)); } catch { parsed = localStorage.getItem(e.key); }
      const truthy = parsed === true || parsed === "true" || parsed === 1 || parsed === "1";
      return { key: e.key, value: String(parsed), truthy };
    });

    // Firebase auth user blob often in indexedDB; we can only hint from local keys
    const firebaseAuthHint = localEntries.some((e) => /firebase:authUser|firebaseLocalStorageDb|firestore_zombie/i.test(e.key))
      || /firestore_zombie|firebase/i.test(localEntries.map((e) => e.key).join(" "));

    return { localEntries, sessionEntries, jwtHits, vipKeys, authKeys, deviceKeys, cacheKeys, vipFlags, firebaseAuthHint };
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
    const patterns = [/\bVIP\b/i, /premium/i, /subscribe|subscription|اشتراك/i, /paywall|locked|مقفل|🔒/i, /paypal|stripe|cib|ccp|بريدي/i, /compte vip|حساب\s*vip|يلزم.*vip|vip account/i];
    const hits = patterns.filter((re) => re.test(bodyText) || re.test(text)).map(String);
    const lockButtons = [...document.querySelectorAll("button, a, [role=button]")]
      .map((el) => (el.innerText || el.textContent || "").trim())
      .filter((t) => t && /vip|premium|subscribe|اشتراك|مقفل|🔒|pro|الحل النموذجي/i.test(t))
      .slice(0, 25);
    return { hits, lockButtons, likelyPaywall: hits.length >= 1 || lockButtons.length > 0 };
  }

  function findPdfLinks(text) {
    const fromText = text.match(PDF_LINK_RE) || [];
    const fromAnchors = [...document.querySelectorAll("a[href]")].map((a) => a.href).filter((h) => /\.pdf($|\?)|firebasestorage|storage\.googleapis|blob:/i.test(h));
    const fromEmbeds = [...document.querySelectorAll("embed[src], iframe[src], object[data]")].map((el) => el.src || el.data).filter((h) => h && /\.pdf|blob:|storage/i.test(h));
    const pdfButtons = [...document.querySelectorAll("button, a, [role=button]")]
      .map((el) => (el.innerText || "").trim())
      .filter((t) => /pdf|طباعة|print|تحميل|download|ورقة الامتحان|ملف/i.test(t))
      .slice(0, 20);
    const usesPrint = /window\.print\s*\(|print\s*\(/i.test(text);
    return {
      links: uniq([...fromText, ...fromAnchors, ...fromEmbeds]).slice(0, 40),
      pdfButtons,
      usesPrint
    };
  }

  function analyzeLinks() {
    const anchors = [...document.querySelectorAll("a[href]")];
    const blankNoopener = [];
    const jsLinks = [];
    const external = [];
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
      } catch {}
    });
    return {
      total: anchors.length,
      blankNoopener: uniq(blankNoopener).slice(0, 15),
      jsLinks: uniq(jsLinks).slice(0, 10),
      externalHosts: uniq(external).slice(0, 20)
    };
  }

  function sniffLibraries(scriptUrls, text) {
    const found = [];
    const hay = scriptUrls.join("\n") + "\n" + text.slice(0, 200000);
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
          out.push(`${key}=${clip(val, 40)}`);
        }
      });
    } catch {}
    return out;
  }

  async function runScan() {
    const timeline = [];
    const findings = [];
    const startedAt = new Date().toISOString();
    const src = collectSource();
    const bodyText = (document.body?.innerText || "").slice(0, 25000);

    // 1 HTTPS
    const isHttps = location.protocol === "https:";
    timeline.push({ id: "https", state: isHttps ? "ok" : "bad", detail: isHttps ? `HTTPS OK (${location.origin})` : `Not HTTPS` });
    findings.push(isHttps
      ? { severity: "info", title: "HTTPS مفعّل", detail: "الاتصال مشفّر.", evidence: location.origin }
      : { severity: "high", title: "الموقع ليس HTTPS", detail: "البيانات قد تُعترض على الشبكة.", evidence: location.href });

    // 2 meta
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]')?.content || null;
    const generator = document.querySelector('meta[name="generator" i]')?.content || null;
    const robots = document.querySelector('meta[name="robots" i]')?.content || null;
    timeline.push({ id: "meta", state: cspMeta ? "ok" : "warn", detail: cspMeta ? "CSP meta موجود" : "لا CSP meta (قد يوجد في الهيدر)" });
    if (!cspMeta) findings.push({ severity: "low", title: "لا يوجد Content-Security-Policy meta", detail: "تحقق من Response Headers في Network. يقلل XSS إن وُجد." });
    else findings.push({ severity: "info", title: "CSP meta موجود", detail: clip(cspMeta, 200) });
    if (generator) findings.push({ severity: "info", title: "Generator", detail: generator });
    if (robots) findings.push({ severity: "info", title: "Robots meta", detail: robots });

    // 3 assets + SW
    const scripts = src.scripts;
    const styles = [...document.querySelectorAll('link[rel~="stylesheet"]')].map((l) => l.href);
    const images = [...document.images].map((i) => i.currentSrc || i.src).filter(Boolean);
    const externalDomains = uniq([...scripts.external, ...styles, ...images].map(domainOf).filter((d) => d && d !== location.hostname));
    let swCount = 0;
    try { if (navigator.serviceWorker) swCount = (await navigator.serviceWorker.getRegistrations()).length; } catch {}
    timeline.push({ id: "assets", state: "ok", detail: `scripts=${scripts.total}, styles=${styles.length}, 3rd=${externalDomains.length}, SW=${swCount}` });
    findings.push({ severity: "info", title: "جرد الأصول العامة", detail: `Scripts ${scripts.total} (inline ${scripts.inlineCount} / external ${scripts.external.length}). CSS ${styles.length}. Third-party ${externalDomains.length}. SW ${swCount}.`, evidence: externalDomains.slice(0, 20).join("\n") || "(none)" });
    if (swCount > 0) findings.push({ severity: "info", title: "Service Worker مسجّل", detail: "قد يخفي التحميلات في الكاش. عطّل cache عند اختبار PDF/API." });

    // 4 libs
    const libs = sniffLibraries(scripts.external, src.combined);
    timeline.push({ id: "libs", state: libs.length ? "ok" : "ok", detail: libs.length ? `${libs.length} library signal(s)` : "No common lib filenames detected" });
    if (libs.length) findings.push({ severity: "info", title: "مكتبات JS مكتشفة (أسماء/إشارات)", detail: "للفحص اليدوي لإصدارات قديمة. ليس CVE كامل مثل Retire.js.", evidence: libs.map((l) => `${l.name}${l.version ? "@" + l.version : ""} :: ${l.evidence}`).join("\n") });

    // 5 endpoints
    const endpoints = findEndpoints(src.combined);
    const interesting = endpoints.filter((u) => /api|firebase|firestore|supabase|cloudfunctions|graphql|auth|token|login|paypal|stripe|googleapis|webchannel|gsessionid/i.test(u) && !/fonts\.googleapis|fonts\.gstatic|woff2?/i.test(u));
    timeline.push({ id: "endpoints", state: interesting.length ? "warn" : "ok", detail: `${endpoints.length} urls, ${interesting.length} api-like` });
    if (interesting.length) findings.push({ severity: "medium", title: "روابط API/Backend محتملة في السورس", detail: "راجع قواعد الحماية.", evidence: interesting.slice(0, 25).join("\n") });
    else findings.push({ severity: "low", title: "لا API واضح في السورس", detail: "قد تُحمَّل ديناميكيًا عبر Firestore webchannel." });

    // 6 firebase
    const fbClues = uniq(src.combined.match(/[a-z0-9-]+\.firebaseapp\.com|[a-z0-9-]+\.web\.app|initializeApp\s*\(|firebase-(?:app|auth|firestore|storage)|firebasestorage|identitytoolkit/gi) || []);
    const projectHints = uniq(src.combined.match(/firestore_zombie_firestore\/\[DEFAULT\]\/([a-z0-9-]+)/gi) || []);
    // also from storage keys
    let storageProject = [];
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i) || "";
        const m = k.match(/firestore_zombie_firestore\/\[DEFAULT\]\/([a-z0-9-]+)/i);
        if (m) storageProject.push(m[1]);
      }
    } catch {}
    storageProject = uniq(storageProject);
    const onFbHost = /\.web\.app$|\.firebaseapp\.com$/i.test(location.hostname);
    timeline.push({ id: "firebase", state: (fbClues.length || onFbHost || storageProject.length) ? "warn" : "ok", detail: storageProject.length ? `project hint: ${storageProject.join(",")}` : (onFbHost ? "firebase hosting host" : `${fbClues.length} clues`) });
    if (onFbHost || fbClues.length || storageProject.length) {
      findings.push({
        severity: "info",
        title: "مؤشرات Firebase",
        detail: "projectId/apiKey العامة طبيعية. الحماية الحقيقية = Security Rules + Auth. لا يعني إمكانية قراءة كل الملفات.",
        evidence: [`host=${location.hostname}`, storageProject.length ? `projectId≈${storageProject.join(",")}` : "", ...fbClues.slice(0, 15)].filter(Boolean).join("\n")
      });
    }

    // 7 secrets
    const secrets = findSecrets(src.combined);
    const urlSecrets = urlParamSecrets();
    timeline.push({ id: "secrets", state: secrets.some((s) => s.severity === "high") || urlSecrets.length ? "bad" : secrets.length ? "warn" : "ok", detail: `${secrets.length} source hits, ${urlSecrets.length} url param hits` });
    secrets.forEach((s) => findings.push({ severity: s.severity, title: `نمط سر محتمل: ${s.type}`, detail: "Heuristic — قد يكون إيجابي كاذب.", evidence: s.sample }));
    if (urlSecrets.length) findings.push({ severity: "high", title: "أسرار/توكنات في رابط الصفحة", detail: "لا تضع tokens في query string.", evidence: urlSecrets.join("\n") });

    // 8 pdf
    const pdf = findPdfLinks(src.combined);
    const publicPdf = pdf.links.filter((u) => /^https?:/i.test(u) && !u.startsWith("blob:"));
    const blobPdf = pdf.links.filter((u) => u.startsWith("blob:"));
    timeline.push({ id: "pdf", state: publicPdf.length ? "warn" : "ok", detail: publicPdf.length ? `${publicPdf.length} public pdf/storage url(s)` : (pdf.usesPrint || pdf.pdfButtons.length ? "print/download UI without direct URL" : "no pdf urls") });
    if (publicPdf.length) findings.push({ severity: "medium", title: "روابط PDF/Storage عامة في السورس", detail: "اختبرها Incognito. الملفات المدفوعة يجب أن تكون signed + rules.", evidence: publicPdf.slice(0, 15).join("\n") });
    else findings.push({ severity: "info", title: "لا رابط PDF مباشر في السورس", detail: "قد يستخدم Print-to-PDF أو blob بعد الضغط. أعد الفحص بعد التحميل وراجع Network." });
    if (blobPdf.length) findings.push({ severity: "low", title: "روابط blob:", detail: "ملفات مؤقتة داخل المتصفح وليست رابطًا عامًا دائمًا.", evidence: blobPdf.slice(0, 8).join("\n") });
    if (pdf.usesPrint) findings.push({ severity: "info", title: "الكود يستدعي window.print", detail: "التحميل غالبًا عبر طباعة/حفظ PDF من المتصفح وليس ملف Storage عام." });
    if (pdf.pdfButtons.length) findings.push({ severity: "info", title: "أزرار PDF/تحميل/طباعة في الواجهة", detail: "مراقبة Network عند الضغط أفضل من البحث في HTML فقط.", evidence: pdf.pdfButtons.slice(0, 12).join(" | ") });

    // 9 account / vip
    const storage = analyzeStorage();
    const account = analyzeAccount(storage, bodyText);
    timeline.push({ id: "account", state: storage.vipFlags.length ? "warn" : "ok", detail: `status=${account.status}, vipFlags=${storage.vipFlags.length}, authKeys=${storage.authKeys.length}` });
    findings.push({
      severity: "info",
      title: "إشارات الحساب / التخزين",
      detail: `accountStatus=${account.status}. VIP flags=${storage.vipFlags.length}. Auth-like keys=${storage.authKeys.length}. Device keys=${storage.deviceKeys.length}.`,
      evidence: [
        ...storage.localEntries.slice(0, 20).map((e) => `${e.key} = ${e.valuePreview}`),
        storage.sessionEntries.length ? "session:" : "",
        ...storage.sessionEntries.slice(0, 10).map((e) => `${e.key} = ${e.valuePreview}`)
      ].filter(Boolean).join("\n") || "(empty)"
    });
    if (storage.vipFlags.length) {
      const anyTrue = storage.vipFlags.some((v) => v.truthy);
      findings.push({
        severity: "medium",
        title: "أعلام VIP/اشتراك في localStorage",
        detail: anyTrue
          ? "يوجد VIP=true على العميل. تأكد أن السيرفر/Firebase يفرض الصلاحية أيضًا."
          : "VIP موجود = false (مقفل). إشارة UI جيدة؛ تحقق server-side ما زال مطلوبًا.",
        evidence: storage.vipFlags.map((v) => `${v.key}=${v.value}`).join("\n")
      });
    }
    if (storage.authKeys.length) findings.push({ severity: "low", title: "مفاتيح auth/session في التخزين", detail: "توكنات localStorage قابلة للسرقة عبر XSS. الأفضل httpOnly حيث يناسب.", evidence: storage.authKeys.map((e) => e.key).join(", ") });
    if (account.status === "logged_in_non_vip_likely") findings.push({ severity: "info", title: "حساب مسجّل غالبًا وغير VIP", detail: "يتوافق مع إشعار يلزم VIP عند فتح الحلول." });

    // 10 jwt
    timeline.push({ id: "jwt", state: storage.jwtHits.length ? "warn" : "ok", detail: `${storage.jwtHits.length} jwt-like in storage` });
    if (storage.jwtHits.length) {
      findings.push({
        severity: "medium",
        title: "JWT داخل التخزين",
        detail: "افحص انتهاء الصلاحية والخوارزمية. لا تشارك التوكن.",
        evidence: storage.jwtHits.slice(0, 8).map((j) => `${j.where} :: ${j.token} :: payloadKeys=${j.payload ? Object.keys(j.payload).join(",") : "?"}`).join("\n")
      });
    } else findings.push({ severity: "info", title: "لا JWT واضح في storage", detail: "قد تُخزَّن الجلسة في IndexedDB/httpOnly cookies." });

    // 11 forms
    const forms = [...document.forms].map((f, idx) => ({ index: idx, action: f.action || "(same)", method: (f.method || "get").toUpperCase(), hasPassword: !!f.querySelector('input[type="password"]'), autocomplete: f.autocomplete || null }));
    const badPass = forms.find((f) => f.hasPassword && location.protocol !== "https:");
    timeline.push({ id: "forms", state: badPass ? "bad" : "ok", detail: `${forms.length} forms` });
    if (forms.length) findings.push({ severity: "info", title: "نماذج Forms", detail: "راجع action/HTTPS.", evidence: forms.slice(0, 10).map((f) => `#${f.index} ${f.method} ${f.action} pass=${f.hasPassword}`).join("\n") });
    if (badPass) findings.push({ severity: "high", title: "كلمة مرور على غير HTTPS", detail: "خطر اعتراض بيانات الدخول." });
    const pwdInputs = [...document.querySelectorAll('input[type="password"]')];
    const acOff = pwdInputs.filter((i) => (i.getAttribute("autocomplete") || "").toLowerCase() === "off");
    if (pwdInputs.length) findings.push({ severity: "low", title: "حقول كلمة المرور", detail: `${pwdInputs.length} password input(s). autocomplete=off count=${acOff.length}.` });

    // 12 links
    const links = analyzeLinks();
    timeline.push({ id: "links", state: links.blankNoopener.length || links.jsLinks.length ? "warn" : "ok", detail: `a=${links.total}, blankNoRel=${links.blankNoopener.length}, javascriptUri=${links.jsLinks.length}` });
    if (links.blankNoopener.length) findings.push({ severity: "low", title: "روابط target=_blank بدون noopener", detail: "أضف rel=noopener noreferrer.", evidence: links.blankNoopener.slice(0, 10).join("\n") });
    if (links.jsLinks.length) findings.push({ severity: "low", title: "روابط javascript:", detail: "يفضّل تجنب javascript: URLs.", evidence: links.jsLinks.join("\n") });

    // 13 cookies
    const rawCookie = document.cookie || "";
    const cookieNames = rawCookie ? rawCookie.split(";").map((x) => x.trim().split("=")[0]).filter(Boolean) : [];
    timeline.push({ id: "cookies", state: "ok", detail: `${cookieNames.length} visible cookies` });
    findings.push({ severity: "info", title: "كوكيز ظاهرة لـ JS", detail: "httpOnly لا تظهر هنا (هذا جيد للأسرار).", evidence: cookieNames.join(", ") || "(none)" });

    // 14 paywall
    const paywall = analyzePaywall(src.combined, bodyText);
    timeline.push({ id: "paywall", state: "ok", detail: paywall.likelyPaywall ? "paywall signals yes" : "no strong paywall text" });
    if (paywall.likelyPaywall) findings.push({ severity: "info", title: "إشارات Paywall/VIP في الواجهة", detail: "ادمج مع VIP flags + رفض السيرفر لتقييم كامل.", evidence: `buttons: ${paywall.lockButtons.slice(0, 12).join(" | ") || "(none)"}\npatterns: ${paywall.hits.length}` });

    // 15 mixed
    const mixed = [];
    if (isHttps) [...scripts.external, ...styles, ...images].forEach((u) => { if (String(u).startsWith("http://")) mixed.push(u); });
    timeline.push({ id: "mixed", state: mixed.length ? "bad" : "ok", detail: mixed.length ? `${mixed.length} mixed` : "no mixed content" });
    if (mixed.length) findings.push({ severity: "high", title: "Mixed content", detail: "HTTPS يحمّل HTTP.", evidence: uniq(mixed).slice(0, 15).join("\n") });

    // 16 summary
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
    let status = "Healthy", state = "ok";
    if (counts.high > 0) { status = "Issues found"; state = "bad"; }
    else if (counts.medium > 0) { status = "Review recommended"; state = "warn"; }
    timeline.push({ id: "summary", state, detail: `${status} · H${counts.high} M${counts.medium} L${counts.low} I${counts.info}` });

    const order = { high: 0, medium: 1, low: 2, info: 3 };
    findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

    return {
      ok: true,
      timeline,
      report: {
        tool: "web-public-security-scanner",
        version: "1.2.0",
        startedAt,
        finishedAt: new Date().toISOString(),
        url: location.href,
        origin: location.origin,
        status,
        counts,
        accountStatus: account.status,
        firebaseProjectHints: storageProjectOr(storageProject),
        inventory: {
          scriptsTotal: scripts.total,
          thirdPartyDomains: externalDomains,
          serviceWorkers: swCount,
          libraries: libs,
          pdfLinks: pdf.links.length,
          vipFlags: storage.vipFlags
        },
        findings
      }
    };

    function storageProjectOr(p) { return p; }
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type !== "RUN_PUBLIC_SECURITY_SCAN") return;
    runScan().then(sendResponse).catch((err) => sendResponse({ ok: false, error: err?.message || String(err) }));
    return true;
  });
})();
