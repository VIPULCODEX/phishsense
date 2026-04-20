const ENABLED_KEY = "phishSenseEnabled";

function tabStateKey(tabId) {
  return `phishSenseTabState:${tabId}`;
}

function setRiskUI(risk) {
  const riskValue = document.getElementById("riskValue");
  const bar = document.getElementById("riskBar");

  riskValue.textContent = `${risk}%`;
  bar.style.width = `${risk}%`;

  if (risk >= 70) {
    bar.style.backgroundColor = "#ef4444";
  } else if (risk >= 40) {
    bar.style.backgroundColor = "#f59e0b";
  } else {
    bar.style.backgroundColor = "#22c55e";
  }
}

function fillReasons(reasons) {
  const ul = document.getElementById("reasons");
  ul.innerHTML = "";

  const safeReasons = reasons && reasons.length ? reasons : ["No major scam indicators found"];
  safeReasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    ul.appendChild(li);
  });
}

function loadTabState(tabId) {
  chrome.storage.local.get([tabStateKey(tabId)], (store) => {
    const state = store[tabStateKey(tabId)];
    const predictionEl = document.getElementById("prediction");
    const urlFlagEl = document.getElementById("urlFlag");

    if (!state) {
      setRiskUI(0);
      predictionEl.textContent = "Prediction: waiting for scan...";
      urlFlagEl.textContent = "URL Flag: --";
      fillReasons(["Open/reload page to generate scan result"]);
      return;
    }

    setRiskUI(state.riskScore || 0);
    predictionEl.textContent = `Prediction: ${state.prediction || "unknown"}`;
    urlFlagEl.textContent = `URL Flag: ${state.urlFlag || "Unknown"}`;
    fillReasons(state.reasons || []);
  });
}

function loadEnabledState() {
  chrome.storage.sync.get([ENABLED_KEY], (store) => {
    const value = typeof store[ENABLED_KEY] === "boolean" ? store[ENABLED_KEY] : true;
    const toggle = document.getElementById("enabledToggle");
    toggle.checked = value;
  });
}

function bindToggle() {
  const toggle = document.getElementById("enabledToggle");
  toggle.addEventListener("change", () => {
    chrome.storage.sync.set({ [ENABLED_KEY]: !!toggle.checked });
  });
}

function setDomain(url) {
  const domainEl = document.getElementById("domain");
  try {
    const host = new URL(url).hostname;
    domainEl.textContent = host;
  } catch (_) {
    domainEl.textContent = url || "Unknown page";
  }
}

function init() {
  bindToggle();
  loadEnabledState();

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (!tab || typeof tab.id !== "number") {
      fillReasons(["Cannot detect active tab"]);
      return;
    }

    setDomain(tab.url || "");
    loadTabState(tab.id);
  });
}

init();

