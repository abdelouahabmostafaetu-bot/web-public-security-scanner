const pageUrlEl = document.getElementById("pageUrl");
const scanBtn = document.getElementById("scanBtn");
const exportBtn = document.getElementById("exportBtn");
const globalStatus = document.getElementById("globalStatus");
const progressText = document.getElementById("progressText");
const progressBar = document.getElementById("progressBar");
const stepsList = document.getElementById("stepsList");
const findingsEl = document.getElementById("findings");
const summaryCards = document.getElementById("summaryCards");

let lastReport = null;

const STEP_DEFS = [
  { id: "https", title: "1) HTTPS" },
  { id: "meta", title: "2) CSP / meta / framing" },
  { id: "assets", title: "3) Assets + Service Worker" },
  { id: "libs", title: "4) JS libraries" },
  { id: "endpoints", title: "5) API / backend URLs" },
  { id: "firebase", title: "6) Firebase clues" },
  { id: "secrets", title: "7) Secrets / keys" },
  { id: "pdf", title: "8) PDF / storage links" },
  { id: "account", title: "9) Account / VIP" },
  { id: "jwt", title: "10) JWT storage" },
  { id: "forms", title: "11) Forms / passwords" },
  { id: "links", title: "12) Dangerous links" },
  { id: "xss", title: "13) DOM XSS sinks" },
  { id: "dangerousjs", title: "14) eval / document.write" },
  { id: "admin", title: "15) Admin / debug paths" },
  { id: "sourcemap", title: "16) Source maps" },
  { id: "pii", title: "17) Emails in page" },
  { id: "iframes", title: "18) Iframes / embeds" },
  { id: "cookies", title: "19) Cookies" },
  { id: "paywall", title: "20) Paywall UI" },
  { id: "mixed", title: "21) Mixed content" },
  { id: "summary", title: "22) Baseline status" },
  { id: "proHeaders", title: "23) PRO: Security headers" },
  { id: "proCors", title: "24) PRO: CORS posture" },
  { id: "proSri", title: "25) PRO: Subresource Integrity" },
  { id: "proSupply", title: "26) PRO: Supply chain surface" },
  { id: "proAuthz", title: "27) PRO: Access control (A01)" },
  { id: "proCrypto", title: "28) PRO: Crypto quality (A02)" },
  { id: "proPrivacy", title: "29) PRO: Powerful APIs" },
  { id: "proStorage", title: "30) PRO: Data at rest" },
  { id: "proFirebase", title: "31) PRO: Firebase config audit" },
  { id: "proSummary", title: "32) PRO: OWASP grade" }
];

function setStatus(kind, text) {
  globalStatus.className = "badge " + kind;
  globalStatus.textContent = text;
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function severityClass(sev) {
  return ["info", "low", "medium", "high"].includes(sev) ? sev : "info";
}

function renderSteps(states) {
  states = states || {};
  stepsList.innerHTML = "";
  STEP_DEFS.forEach(function (s) {
    var st = states[s.id] || { state: "wait", detail: "Waiting..." };
    var li = document.createElement("li");
    li.className = st.state;
    li.innerHTML =
      '<div class="title">' + escapeHtml(s.title) + '</div><div class="meta">' + escapeHtml(st.detail || "") + "</div>";
    stepsList.appendChild(li);
  });
}

function renderReport(report) {
  lastReport = report;
  exportBtn.disabled = !report;
  var c = report.counts || { high: 0, medium: 0, low: 0, info: 0 };
  var grade = report.grade ? report.grade : "-";
  var score = typeof report.score === "number" ? report.score : "-";
  summaryCards.innerHTML =
    '<div class="card bad"><div class="n">' + (c.high || 0) + '</div><div class="t">High</div></div>' +
    '<div class="card warn"><div class="n">' + (c.medium || 0) + '</div><div class="t">Medium</div></div>' +
    '<div class="card ok"><div class="n">' + ((c.low || 0) + (c.info || 0)) + '</div><div class="t">Low/Info</div></div>' +
    '<div class="card ok"><div class="n">' + escapeHtml(grade) + '</div><div class="t">Grade ' + escapeHtml(String(score)) + '</div></div>';

  findingsEl.innerHTML = "";
  (report.findings || []).forEach(function (f) {
    var div = document.createElement("div");
    div.className = "finding";
    div.innerHTML =
      '<span class="sev ' + severityClass(f.severity) + '">' + escapeHtml((f.severity || "info").toUpperCase()) + "</span>" +
      "<h3>" + escapeHtml(f.title || "") + "</h3>" +
      "<p>" + escapeHtml(f.detail || "") + "</p>" +
      (f.evidence ? "<code>" + escapeHtml(f.evidence) + "</code>" : "");
    findingsEl.appendChild(div);
  });
  if (!(report.findings && report.findings.length)) {
    findingsEl.innerHTML =
      '<div class="finding"><span class="sev low">OK</span><h3>No findings</h3><p>Public checks only.</p></div>';
  }
}

function showError(msg) {
  setStatus("error", "Error");
  findingsEl.innerHTML =
    '<div class="finding"><span class="sev high">ERROR</span><h3>Scan failed</h3><p>' +
    escapeHtml(msg || "Unknown error") +
    "</p><p>Fix: chrome://extensions then Reload extension, hard refresh the site (Ctrl+Shift+R), and scan again.</p></div>";
}

async function getActiveTab() {
  var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs && tabs[0];
}

async function init() {
  renderSteps();
  var tab = await getActiveTab();
  pageUrlEl.textContent = (tab && tab.url) || "No active tab";
}

scanBtn.addEventListener("click", async function () {
  var tab = await getActiveTab();
  if (!tab || !tab.id || !tab.url || /^(chrome|edge|about|chrome-extension|devtools):/i.test(tab.url)) {
    showError("Open a normal http(s) website tab first, then run the scan there.");
    return;
  }

  scanBtn.disabled = true;
  exportBtn.disabled = true;
  findingsEl.innerHTML = "";
  summaryCards.innerHTML = "";
  setStatus("running", "Running");

  var states = {};
  STEP_DEFS.forEach(function (s) {
    states[s.id] = { state: "wait", detail: "Queued" };
  });
  renderSteps(states);
  progressText.textContent = "0 / " + STEP_DEFS.length;
  progressBar.style.width = "0%";

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content.js", "pro-checks.js"]
    });

    var baseRun = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: async function () {
        if (typeof globalThis.__runPublicSecurityScan !== "function") {
          return { ok: false, error: "Baseline scanner missing. Reload extension and page." };
        }
        try {
          return await globalThis.__runPublicSecurityScan();
        } catch (e) {
          return { ok: false, error: (e && e.message) || String(e) };
        }
      }
    });

    var base = baseRun && baseRun[0] && baseRun[0].result;
    if (!base) throw new Error("No result from page. Reload extension and hard refresh the page.");
    if (!base.ok) throw new Error(base.error || "Baseline scan failed");

    var baseFindings = (base.report && base.report.findings) || [];

    var proRun = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      args: [baseFindings],
      func: async function (bf) {
        if (typeof globalThis.__runProChecks !== "function") {
          return { ok: false, error: "Professional module missing" };
        }
        try {
          return await globalThis.__runProChecks(bf);
        } catch (e) {
          return { ok: false, error: (e && e.message) || String(e) };
        }
      }
    });

    var pro = (proRun && proRun[0] && proRun[0].result) || { ok: false, error: "pro module unavailable" };

    var timeline = (base.timeline || []).concat(pro.ok ? pro.timeline || [] : []);
    var findings = baseFindings.concat(pro.ok ? pro.findings || [] : []);

    if (!pro.ok) {
      findings.push({
        severity: "info",
        title: "Professional module did not run",
        detail: "Baseline results are still valid.",
        evidence: String(pro.error || "unknown")
      });
    }

    for (var i = 0; i < timeline.length; i++) {
      var t = timeline[i];
      states[t.id] = { state: t.state || "ok", detail: t.detail || "Done" };
      renderSteps(states);
      progressText.textContent = Math.min(i + 1, STEP_DEFS.length) + " / " + STEP_DEFS.length;
      progressBar.style.width = Math.round((Math.min(i + 1, STEP_DEFS.length) / STEP_DEFS.length) * 100) + "%";
      await new Promise(function (r) {
        setTimeout(r, 30);
      });
    }

    STEP_DEFS.forEach(function (s) {
      if (!states[s.id] || states[s.id].state === "wait") states[s.id] = { state: "ok", detail: "Done" };
    });
    renderSteps(states);
    progressText.textContent = STEP_DEFS.length + " / " + STEP_DEFS.length;
    progressBar.style.width = "100%";

    var counts = { high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(function (f) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    var order = { high: 0, medium: 1, low: 2, info: 3 };
    findings.sort(function (a, b) {
      return (order[a.severity] != null ? order[a.severity] : 9) - (order[b.severity] != null ? order[b.severity] : 9);
    });

    var status = counts.high > 0 ? "Issues found" : counts.medium > 0 ? "Review recommended" : "Healthy";

    var report = Object.assign({}, base.report || {}, {
      version: "1.4.0",
      status: status,
      counts: counts,
      findings: findings,
      grade: pro.ok && pro.meta ? pro.meta.grade : null,
      score: pro.ok && pro.meta ? pro.meta.score : null,
      owasp: pro.ok && pro.meta ? pro.meta.owasp : [],
      firebaseConfig: pro.ok && pro.meta ? pro.meta.firebaseConfig : {}
    });

    renderReport(report);
    setStatus("done", (report.grade ? "Grade " + report.grade : status));
  } catch (err) {
    console.error(err);
    showError((err && err.message) || String(err));
  } finally {
    scanBtn.disabled = false;
  }
});

exportBtn.addEventListener("click", function () {
  if (!lastReport) return;
  var blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url;
  a.download = "security-report-" + Date.now() + ".json";
  a.click();
  URL.revokeObjectURL(url);
});

init();
