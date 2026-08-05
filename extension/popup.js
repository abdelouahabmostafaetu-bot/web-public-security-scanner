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
  { id: "pii", title: "17) Emails / phones in page" },
  { id: "iframes", title: "18) Iframes / embeds" },
  { id: "cookies", title: "19) Cookies" },
  { id: "paywall", title: "20) Paywall UI" },
  { id: "mixed", title: "21) Mixed content" },
  { id: "summary", title: "22) Final status" }
];

function setStatus(kind, text) {
  globalStatus.className = `badge ${kind}`;
  globalStatus.textContent = text;
}

function renderSteps(states = {}) {
  stepsList.innerHTML = "";
  STEP_DEFS.forEach((s) => {
    const st = states[s.id] || { state: "wait", detail: "Waiting…" };
    const li = document.createElement("li");
    li.className = st.state;
    li.innerHTML = `<div class="title">${s.title}</div><div class="meta">${escapeHtml(st.detail || "")}</div>`;
    stepsList.appendChild(li);
  });
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

function renderReport(report) {
  lastReport = report;
  exportBtn.disabled = !report;
  const c = report.counts || { high: 0, medium: 0, low: 0, info: 0 };
  summaryCards.innerHTML = `
    <div class="card bad"><div class="n">${c.high || 0}</div><div class="t">High</div></div>
    <div class="card warn"><div class="n">${c.medium || 0}</div><div class="t">Medium</div></div>
    <div class="card ok"><div class="n">${(c.low || 0) + (c.info || 0)}</div><div class="t">Low/Info</div></div>
  `;
  findingsEl.innerHTML = "";
  (report.findings || []).forEach((f) => {
    const div = document.createElement("div");
    div.className = "finding";
    div.innerHTML = `
      <span class="sev ${severityClass(f.severity)}">${escapeHtml((f.severity || "info").toUpperCase())}</span>
      <h3>${escapeHtml(f.title)}</h3>
      <p>${escapeHtml(f.detail || "")}</p>
      ${f.evidence ? `<code>${escapeHtml(f.evidence)}</code>` : ""}
    `;
    findingsEl.appendChild(div);
  });
  if (!report.findings?.length) {
    findingsEl.innerHTML = `<div class="finding"><span class="sev low">OK</span><h3>No findings</h3><p>Public checks only.</p></div>`;
  }
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function init() {
  renderSteps();
  const tab = await getActiveTab();
  pageUrlEl.textContent = tab?.url || "No active tab";
}

scanBtn.addEventListener("click", async () => {
  const tab = await getActiveTab();
  if (!tab?.id || !tab.url || /^(chrome|edge|about|chrome-extension):/i.test(tab.url)) {
    setStatus("error", "Error");
    alert("Open a normal http(s) website first.");
    return;
  }
  scanBtn.disabled = true;
  exportBtn.disabled = true;
  findingsEl.innerHTML = "";
  summaryCards.innerHTML = "";
  setStatus("running", "Running");
  const states = {};
  STEP_DEFS.forEach((s) => { states[s.id] = { state: "wait", detail: "Queued" }; });
  renderSteps(states);
  progressText.textContent = `0 / ${STEP_DEFS.length}`;
  progressBar.style.width = "0%";
  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
    const response = await chrome.tabs.sendMessage(tab.id, { type: "RUN_PUBLIC_SECURITY_SCAN" });
    if (!response?.ok) throw new Error(response?.error || "Scan failed");
    const timeline = response.timeline || [];
    for (let i = 0; i < timeline.length; i++) {
      const t = timeline[i];
      states[t.id] = { state: t.state || "ok", detail: t.detail || "Done" };
      renderSteps(states);
      progressText.textContent = `${i + 1} / ${STEP_DEFS.length}`;
      progressBar.style.width = `${Math.round(((i + 1) / STEP_DEFS.length) * 100)}%`;
      await new Promise((r) => setTimeout(r, 55));
    }
    renderReport(response.report);
    setStatus("done", response.report?.status || "Done");
  } catch (err) {
    console.error(err);
    setStatus("error", "Error");
    findingsEl.innerHTML = `<div class="finding"><span class="sev high">ERROR</span><h3>Scan failed</h3><p>${escapeHtml(err.message || String(err))}</p></div>`;
  } finally {
    scanBtn.disabled = false;
  }
});

exportBtn.addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `public-security-scan-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

init();
