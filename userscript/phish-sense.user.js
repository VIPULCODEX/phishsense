// ==UserScript==
// @name         Phish Sense Realtime Scanner
// @namespace    https://github.com/VIPULCODEX/phishsense
// @version      1.2.0
// @description  Realtime phishing/scam risk scanner for Tampermonkey/Greasemonkey
// @author       VIPULCODEX
// @updateURL    https://raw.githubusercontent.com/VIPULCODEX/phishsense/main/userscript/phish-sense.user.js
// @downloadURL  https://raw.githubusercontent.com/VIPULCODEX/phishsense/main/userscript/phish-sense.user.js
// @match        *://*/*
// @run-at       document-idle
// @grant        none
// ==/UserScript==

(function () {
  "use strict";

  const URL_REGEX = /\b((?:https?:\/\/|www\.)[^\s<>"']+)/gi;
  const MAX_TEXT_CHARS = 26000;
  const MAX_ANCHORS = 300;
  const RESCAN_DEBOUNCE_MS = 1200;

  const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "is.gd", "ow.ly"]);
  const SUSPICIOUS_TLDS = new Set(["xyz", "top", "click", "work", "gq", "tk", "ml", "cf", "buzz"]);
  const URGENCY = new Set(["urgent", "immediately", "immediate", "asap", "now", "limited", "alert", "warning"]);
  const ACTION = new Set(["click", "verify", "confirm", "share", "send", "provide", "update", "login"]);
  const PHISH = new Set(["verify", "account", "kyc", "login", "confirm", "identity", "password", "bank"]);
  const OTP = new Set(["otp", "0tp"]);
  const LOTTERY = new Set(["lottery", "winner", "prize", "jackpot", "claim", "reward", "bonus"]);
  const JOB = new Set(["job", "hiring", "earn", "income", "salary", "registration", "fee"]);

  const BENIGN_CONTEXT = new Set([
    "repository",
    "github",
    "readme",
    "issue",
    "commit",
    "pull",
    "documentation",
    "tutorial",
    "example",
    "sample",
    "reference",
    "guide",
    "course",
    "lesson",
    "blog",
    "article"
  ]);

  const TRUSTED_HOST_HINTS = new Set([
    "github.com",
    "stackoverflow.com",
    "developer.mozilla.org",
    "docs.python.org",
    "wikipedia.org",
    "medium.com"
  ]);

  const COLORS = {
    low: { dot: "#16a34a", glow: "rgba(22,163,74,0.35)", outline: "#22c55e" },
    caution: { dot: "#d97706", glow: "rgba(217,119,6,0.35)", outline: "#f59e0b" },
    high: { dot: "#dc2626", glow: "rgba(220,38,38,0.35)", outline: "#ef4444" }
  };

  const state = {
    paused: false,
    pinned: false,
    autoHighlightTop: false,
    expanded: false,
    scanTimer: null,
    observer: null,
    ui: null,
    result: null,
    highlightedElements: new Set(),
    originalStyles: new WeakMap()
  };

  function tokenize(text) {
    return (text.match(/[a-z0-9]+/g) || []).map((t) => t.toLowerCase());
  }

  function countHits(tokens, set) {
    let count = 0;
    for (const token of tokens) {
      if (set.has(token)) count += 1;
    }
    return count;
  }

  function normalize(url) {
    try {
      if (!url.startsWith("http://") && !url.startsWith("https://")) {
        return new URL(`https://${url}`);
      }
      return new URL(url);
    } catch (_) {
      return null;
    }
  }

  function isLikelyTrustedHost(hostname) {
    const host = hostname.replace(/^www\./, "");
    return [...TRUSTED_HOST_HINTS].some((known) => host === known || host.endsWith(`.${known}`));
  }

  function getScannableTextNodes() {
    if (!document.body) return [];

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const nodes = [];
    let total = 0;
    let node = walker.nextNode();

    while (node && total < MAX_TEXT_CHARS) {
      const parent = node.parentElement;
      if (!parent) {
        node = walker.nextNode();
        continue;
      }

      const tag = parent.tagName;
      if (
        tag === "SCRIPT" ||
        tag === "STYLE" ||
        tag === "NOSCRIPT" ||
        tag === "CODE" ||
        tag === "PRE" ||
        tag === "TEXTAREA" ||
        tag === "SVG"
      ) {
        node = walker.nextNode();
        continue;
      }

      const value = (node.nodeValue || "").replace(/\s+/g, " ").trim();
      if (!value) {
        node = walker.nextNode();
        continue;
      }

      nodes.push({
        text: value,
        lower: value.toLowerCase(),
        element: parent
      });

      total += value.length;
      node = walker.nextNode();
    }

    return nodes;
  }

  function findElementsByKeywords(textNodes, keywords) {
    const elements = [];
    const matchedKeywords = new Set();

    for (const item of textNodes) {
      for (const keyword of keywords) {
        if (item.lower.includes(keyword)) {
          matchedKeywords.add(keyword);
          elements.push(item.element);
          break;
        }
      }
      if (elements.length >= 30) break;
    }

    return {
      elements,
      matchedKeywords: [...matchedKeywords]
    };
  }

  function mergeUniqueElements(base, extra) {
    const merged = new Set(base || []);
    (extra || []).forEach((el) => {
      if (el && el.isConnected) merged.add(el);
    });
    return [...merged];
  }

  function createReasonStore() {
    const reasons = new Map();

    function addReason({ id, title, impact = 0, detail = "", elements = [], type = "threat" }) {
      const existing = reasons.get(id);
      if (existing) {
        existing.impact += impact;
        existing.elements = mergeUniqueElements(existing.elements, elements);
        if (detail && !existing.details.includes(detail)) existing.details.push(detail);
      } else {
        reasons.set(id, {
          id,
          title,
          type,
          impact,
          details: detail ? [detail] : [],
          elements: mergeUniqueElements([], elements)
        });
      }
    }

    function toArrays() {
      const threat = [];
      const mitigation = [];
      reasons.forEach((reason) => {
        if (reason.type === "mitigation") mitigation.push(reason);
        else threat.push(reason);
      });

      threat.sort((a, b) => b.impact - a.impact);
      mitigation.sort((a, b) => b.impact - a.impact);
      return { threat, mitigation };
    }

    return { addReason, toArrays };
  }

  function analyzeUrls(fullText, tokens) {
    const anchors = Array.from(document.querySelectorAll("a[href]")).slice(0, MAX_ANCHORS);
    const urls = new Set((fullText.match(URL_REGEX) || []).map((u) => u.trim()));
    anchors.forEach((a) => urls.add(a.getAttribute("href") || ""));

    let suspiciousUrlCount = 0;
    let mismatchCount = 0;
    const suspiciousHosts = new Set();
    const suspiciousElements = [];
    const mismatchElements = [];
    const currentHost = location.hostname.replace(/^www\./, "").toLowerCase();

    anchors.forEach((a) => {
      const href = a.getAttribute("href") || "";
      const parsed = normalize(href);
      if (!parsed) return;

      const host = parsed.hostname.replace(/^www\./, "").toLowerCase();
      const tld = host.includes(".") ? host.split(".").pop() : "";
      const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
      const isSuspicious = SHORTENERS.has(host) || SUSPICIOUS_TLDS.has(tld) || isIp || host.includes("xn--");

      if (isSuspicious) {
        suspiciousUrlCount += 1;
        suspiciousHosts.add(host);
        suspiciousElements.push(a);
      }

      const visible = (a.textContent || "").trim();
      const shownMatch = visible.match(URL_REGEX);
      if (!shownMatch || !shownMatch[0]) return;

      const shown = normalize(shownMatch[0]);
      if (!shown) return;

      const realHost = host;
      const shownHost = shown.hostname.replace(/^www\./, "").toLowerCase();
      if (realHost && shownHost && realHost !== shownHost) {
        mismatchCount += 1;
        mismatchElements.push(a);
      }
    });

    let externalActionLinks = 0;
    if (tokens.includes("click") || tokens.includes("verify") || tokens.includes("login")) {
      anchors.forEach((a) => {
        const parsed = normalize(a.getAttribute("href") || "");
        if (!parsed) return;
        const host = parsed.hostname.replace(/^www\./, "").toLowerCase();
        if (host && host !== currentHost) externalActionLinks += 1;
      });
    }

    return {
      urlsCount: urls.size,
      suspiciousUrlCount,
      mismatchCount,
      externalActionLinks,
      suspiciousHosts: [...suspiciousHosts].slice(0, 4),
      suspiciousElements: mergeUniqueElements([], suspiciousElements),
      mismatchElements: mergeUniqueElements([], mismatchElements)
    };
  }

  function analyzePage() {
    const textNodes = getScannableTextNodes();
    const fullText = textNodes.map((n) => n.lower).join(" ").slice(0, MAX_TEXT_CHARS);
    const tokens = tokenize(fullText);
    const domain = location.hostname.replace(/^www\./, "").toLowerCase();

    const urgencyHits = countHits(tokens, URGENCY);
    const actionHits = countHits(tokens, ACTION);
    const phishHits = countHits(tokens, PHISH);
    const otpHits = countHits(tokens, OTP);
    const lotteryHits = countHits(tokens, LOTTERY);
    const jobHits = countHits(tokens, JOB);
    const benignHits = countHits(tokens, BENIGN_CONTEXT);
    const moneyMention = /\b(rs|₹|usd|cash|lakh|bonus|reward|prize|salary)\b/i.test(fullText);
    const obfuscatedHits = (fullText.match(/\b(cl1ck|0tp|fr33|v3rify)\b/gi) || []).length;
    const hasPasswordField = !!document.querySelector("input[type='password']");

    const urgencyEvidence = findElementsByKeywords(textNodes, URGENCY);
    const phishEvidence = findElementsByKeywords(textNodes, PHISH);
    const otpEvidence = findElementsByKeywords(textNodes, OTP);
    const lureEvidence = findElementsByKeywords(textNodes, new Set([...LOTTERY, ...JOB]));

    const urlReport = analyzeUrls(fullText, tokens);
    const store = createReasonStore();

    let rawScore = 0;

    if (otpHits > 0 && (actionHits > 0 || urgencyHits > 0)) {
      rawScore += 28;
      store.addReason({
        id: "otp_solicit",
        title: "OTP solicitation pattern",
        impact: 28,
        detail: `${otpHits} OTP hit(s) with action/urgency context`,
        elements: otpEvidence.elements
      });
    }

    if (phishHits >= 2 && (urgencyHits > 0 || actionHits > 0)) {
      rawScore += 20;
      store.addReason({
        id: "credential_pressure",
        title: "Credential/account pressure pattern",
        impact: 20,
        detail: `${phishHits} account-security keyword hit(s)`,
        elements: phishEvidence.elements
      });
    } else if (phishHits >= 3) {
      rawScore += 12;
      store.addReason({
        id: "multiple_security_terms",
        title: "Multiple account-security terms",
        impact: 12,
        detail: `${phishHits} account-security keyword hit(s)`,
        elements: phishEvidence.elements
      });
    }

    if ((lotteryHits > 0 || jobHits > 0) && (moneyMention || actionHits > 0)) {
      const lureHits = lotteryHits + jobHits;
      rawScore += 18;
      store.addReason({
        id: "financial_lure",
        title: "Financial lure pattern",
        impact: 18,
        detail: `${lureHits} lure keyword hit(s)`,
        elements: lureEvidence.elements
      });
    }

    if (obfuscatedHits > 0) {
      rawScore += 10;
      store.addReason({
        id: "obfuscation",
        title: "Obfuscated wording detected",
        impact: 10,
        detail: `${obfuscatedHits} obfuscated token hit(s)`,
        elements: mergeUniqueElements([], [...urgencyEvidence.elements, ...phishEvidence.elements, ...otpEvidence.elements])
      });
    }

    if (urlReport.suspiciousUrlCount > 0) {
      rawScore += 24;
      store.addReason({
        id: "suspicious_urls",
        title: "Suspicious URL patterns",
        impact: 24,
        detail: `${urlReport.suspiciousUrlCount} suspicious link(s) found`,
        elements: urlReport.suspiciousElements
      });
    }

    if (urlReport.mismatchCount > 0) {
      rawScore += 18;
      store.addReason({
        id: "anchor_mismatch",
        title: "Anchor text URL mismatch",
        impact: 18,
        detail: `${urlReport.mismatchCount} mismatched anchor link(s)`,
        elements: urlReport.mismatchElements
      });
    }

    if (hasPasswordField && (actionHits > 0 || phishHits > 0)) {
      rawScore += 10;
      store.addReason({
        id: "password_prompt",
        title: "Password prompt with action language",
        impact: 10,
        detail: "Password field present with suspicious prompt context",
        elements: Array.from(document.querySelectorAll("input[type='password']")).slice(0, 10)
      });
    }

    if (urlReport.urlsCount > 0 && (actionHits > 0 || urgencyHits > 0)) {
      rawScore += 3;
      store.addReason({
        id: "external_action_links",
        title: "External links with action language",
        impact: 3,
        detail: `${urlReport.externalActionLinks} external action-oriented link(s)`,
        elements: []
      });
    }

    const arraysBeforeMitigation = store.toArrays();
    const signalCount = arraysBeforeMitigation.threat.length;

    if (signalCount <= 1 && rawScore > 0) {
      rawScore *= 0.58;
      store.addReason({
        id: "single_signal_dampen",
        title: "Single-signal dampening applied",
        impact: 8,
        detail: "Only one major signal found; score reduced",
        type: "mitigation"
      });
    }

    if (benignHits >= 5) {
      rawScore -= 15;
      store.addReason({
        id: "benign_context_strong",
        title: "Benign context detected",
        impact: 15,
        detail: `${benignHits} benign-context hit(s)`,
        type: "mitigation"
      });
    } else if (benignHits >= 2) {
      rawScore -= 8;
      store.addReason({
        id: "benign_context_light",
        title: "Some benign context detected",
        impact: 8,
        detail: `${benignHits} benign-context hit(s)`,
        type: "mitigation"
      });
    }

    if (isLikelyTrustedHost(domain)) {
      rawScore -= 10;
      store.addReason({
        id: "trusted_host_adjust",
        title: "Trusted host adjustment",
        impact: 10,
        detail: "Trusted host signal used as dampener, not bypass",
        type: "mitigation"
      });
    }

    const arraysAfterMitigation = store.toArrays();

    if (signalCount >= 3 && urlReport.suspiciousUrlCount > 0) {
      rawScore += 6;
      store.addReason({
        id: "multisignal_boost",
        title: "Multi-signal correlation boost",
        impact: 6,
        detail: "Multiple threat signals plus suspicious URLs increased confidence"
      });
    }

    const finalArrays = store.toArrays();
    const score = Math.max(0, Math.min(100, Math.round(rawScore)));
    const level = score >= 72 ? "HIGH RISK" : score >= 42 ? "CAUTION" : "LOW RISK";
    const colorKey = score >= 72 ? "high" : score >= 42 ? "caution" : "low";

    const threatCount = finalArrays.threat.length;
    let confidence = "minimal";
    if (threatCount >= 4) confidence = "high";
    else if (threatCount >= 2) confidence = "medium";
    else if (threatCount === 1) confidence = "low";

    return {
      score,
      level,
      colorKey,
      confidence,
      signalCount: threatCount,
      threatReasons: finalArrays.threat,
      mitigationReasons: finalArrays.mitigation,
      suspiciousHosts: urlReport.suspiciousHosts,
      scannedAt: new Date().toLocaleTimeString()
    };
  }

  function injectStyles() {
    if (document.getElementById("ps-style")) return;

    const style = document.createElement("style");
    style.id = "ps-style";
    style.textContent = `
      #ps-root {
        position: fixed;
        right: 14px;
        bottom: 14px;
        z-index: 2147483647;
        font-family: Segoe UI, Arial, sans-serif;
        color: #e2e8f0;
        user-select: none;
      }
      #ps-pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        border-radius: 999px;
        border: 1px solid #334155;
        background: #0f172a;
        padding: 8px 12px;
        cursor: pointer;
        box-shadow: 0 10px 24px rgba(0,0,0,0.35);
      }
      #ps-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
      }
      #ps-pill-score {
        font-size: 13px;
        font-weight: 700;
      }
      #ps-pill-level {
        font-size: 12px;
        opacity: 0.9;
      }
      #ps-panel {
        width: 360px;
        max-width: min(360px, 92vw);
        margin-top: 8px;
        background: rgba(15,23,42,0.97);
        border: 1px solid #334155;
        border-radius: 12px;
        box-shadow: 0 16px 34px rgba(0,0,0,0.45);
        padding: 12px;
        display: none;
      }
      #ps-root[data-expanded="true"] #ps-panel {
        display: block;
      }
      .ps-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
      }
      .ps-title {
        font-size: 14px;
        font-weight: 700;
      }
      .ps-sub {
        font-size: 12px;
        opacity: 0.85;
        margin-top: 2px;
      }
      .ps-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 10px;
      }
      .ps-btn {
        border: 1px solid #475569;
        border-radius: 8px;
        background: #0b1328;
        color: #cbd5e1;
        font-size: 12px;
        padding: 6px 8px;
        cursor: pointer;
      }
      .ps-btn:hover { border-color: #60a5fa; }
      .ps-toggle {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        margin-top: 8px;
      }
      .ps-section-title {
        margin-top: 10px;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #93c5fd;
      }
      .ps-list {
        margin-top: 6px;
        display: grid;
        gap: 6px;
        max-height: 180px;
        overflow: auto;
        padding-right: 2px;
      }
      .ps-reason {
        border: 1px solid #334155;
        border-radius: 8px;
        background: #0b1328;
        padding: 8px;
        cursor: pointer;
      }
      .ps-reason:hover { border-color: #60a5fa; }
      .ps-reason-title {
        font-size: 12px;
        font-weight: 600;
      }
      .ps-reason-meta {
        margin-top: 3px;
        font-size: 11px;
        opacity: 0.82;
      }
      .ps-empty {
        font-size: 12px;
        opacity: 0.75;
      }
      .ps-foot {
        margin-top: 8px;
        font-size: 11px;
        opacity: 0.72;
      }
    `;
    document.documentElement.appendChild(style);
  }

  function ensureUI() {
    if (state.ui) return state.ui;

    injectStyles();

    const root = document.createElement("div");
    root.id = "ps-root";
    root.dataset.expanded = "false";

    const pill = document.createElement("div");
    pill.id = "ps-pill";

    const dot = document.createElement("span");
    dot.id = "ps-dot";

    const score = document.createElement("span");
    score.id = "ps-pill-score";
    score.textContent = "0%";

    const level = document.createElement("span");
    level.id = "ps-pill-level";
    level.textContent = "LOW RISK";

    pill.appendChild(dot);
    pill.appendChild(score);
    pill.appendChild(level);

    const panel = document.createElement("div");
    panel.id = "ps-panel";

    panel.innerHTML = `
      <div class="ps-head">
        <div>
          <div class="ps-title">Phish Sense Explainability</div>
          <div class="ps-sub" id="ps-summary">Signals: 0 | Confidence: minimal</div>
        </div>
        <button class="ps-btn" id="ps-pin">Pin</button>
      </div>

      <div class="ps-actions">
        <button class="ps-btn" id="ps-highlight-all">Show Threat Areas</button>
        <button class="ps-btn" id="ps-clear">Clear Highlights</button>
        <button class="ps-btn" id="ps-rescan">Rescan</button>
      </div>

      <label class="ps-toggle">
        <input type="checkbox" id="ps-auto-highlight" />
        Auto-highlight top threat after scan
      </label>
      <label class="ps-toggle">
        <input type="checkbox" id="ps-pause" />
        Pause scanning
      </label>

      <div class="ps-section-title">Threat Signals</div>
      <div class="ps-list" id="ps-threat-list"></div>

      <div class="ps-section-title">Mitigation Context</div>
      <div class="ps-list" id="ps-mitigation-list"></div>

      <div class="ps-foot" id="ps-foot">Last scan: --</div>
    `;

    root.appendChild(pill);
    root.appendChild(panel);
    document.documentElement.appendChild(root);

    const ui = {
      root,
      pill,
      dot,
      score,
      level,
      panel,
      summary: panel.querySelector("#ps-summary"),
      threatList: panel.querySelector("#ps-threat-list"),
      mitigationList: panel.querySelector("#ps-mitigation-list"),
      foot: panel.querySelector("#ps-foot"),
      pinBtn: panel.querySelector("#ps-pin"),
      highlightAllBtn: panel.querySelector("#ps-highlight-all"),
      clearBtn: panel.querySelector("#ps-clear"),
      rescanBtn: panel.querySelector("#ps-rescan"),
      autoHighlight: panel.querySelector("#ps-auto-highlight"),
      pauseCheck: panel.querySelector("#ps-pause")
    };

    pill.addEventListener("click", () => {
      setExpanded(!state.expanded);
    });

    root.addEventListener("mouseenter", () => {
      if (!state.pinned) setExpanded(true);
    });

    root.addEventListener("mouseleave", () => {
      if (!state.pinned) setExpanded(false);
    });

    ui.pinBtn.addEventListener("click", () => {
      state.pinned = !state.pinned;
      ui.pinBtn.textContent = state.pinned ? "Unpin" : "Pin";
      if (!state.pinned) setExpanded(false);
    });

    ui.highlightAllBtn.addEventListener("click", () => {
      if (!state.result) return;
      highlightThreats(state.result.threatReasons, true);
    });

    ui.clearBtn.addEventListener("click", () => {
      clearHighlights();
    });

    ui.rescanBtn.addEventListener("click", () => {
      runScan();
    });

    ui.autoHighlight.addEventListener("change", () => {
      state.autoHighlightTop = !!ui.autoHighlight.checked;
    });

    ui.pauseCheck.addEventListener("change", () => {
      state.paused = !!ui.pauseCheck.checked;
      if (!state.paused) scheduleScan(true);
    });

    state.ui = ui;
    return ui;
  }

  function setExpanded(expanded) {
    state.expanded = expanded;
    const ui = ensureUI();
    ui.root.dataset.expanded = expanded ? "true" : "false";
  }

  function saveOriginalStyle(el) {
    if (!state.originalStyles.has(el)) {
      state.originalStyles.set(el, {
        outline: el.style.outline,
        boxShadow: el.style.boxShadow,
        backgroundColor: el.style.backgroundColor,
        transition: el.style.transition
      });
    }
  }

  function applyHighlight(elements, color) {
    const capped = (elements || []).filter((el) => el && el.isConnected).slice(0, 25);
    capped.forEach((el) => {
      saveOriginalStyle(el);
      el.style.transition = "outline 0.2s ease, box-shadow 0.2s ease, background-color 0.2s ease";
      el.style.outline = `2px solid ${color.outline}`;
      el.style.boxShadow = `0 0 0 3px ${color.glow}`;
      if (!el.querySelector("img, video, canvas, svg")) {
        el.style.backgroundColor = "rgba(248,250,252,0.06)";
      }
      state.highlightedElements.add(el);
    });

    if (capped[0]) {
      try {
        capped[0].scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
      } catch (_) {
        // no-op
      }
    }
  }

  function clearHighlights() {
    state.highlightedElements.forEach((el) => {
      const original = state.originalStyles.get(el);
      if (!original) return;
      el.style.outline = original.outline;
      el.style.boxShadow = original.boxShadow;
      el.style.backgroundColor = original.backgroundColor;
      el.style.transition = original.transition;
    });
    state.highlightedElements.clear();
  }

  function highlightReason(reason) {
    clearHighlights();
    const color = COLORS[state.result?.colorKey || "low"];
    applyHighlight(reason.elements || [], color);
  }

  function highlightThreats(threatReasons, includeAll) {
    clearHighlights();
    const color = COLORS[state.result?.colorKey || "low"];
    const reasons = includeAll ? threatReasons : threatReasons.slice(0, 1);
    const all = [];
    reasons.forEach((r) => all.push(...(r.elements || [])));
    applyHighlight(mergeUniqueElements([], all), color);
  }

  function reasonCard(reason, clickable) {
    const card = document.createElement("div");
    card.className = "ps-reason";

    const title = document.createElement("div");
    title.className = "ps-reason-title";
    title.textContent = `${reason.title} (+${reason.impact})`;

    const meta = document.createElement("div");
    meta.className = "ps-reason-meta";
    const details = reason.details && reason.details.length ? reason.details[0] : "No extra detail";
    const areaCount = reason.elements && reason.elements.length ? ` | Areas: ${reason.elements.length}` : "";
    meta.textContent = `${details}${areaCount}`;

    card.appendChild(title);
    card.appendChild(meta);

    if (clickable && reason.elements && reason.elements.length) {
      card.addEventListener("click", () => highlightReason(reason));
    } else {
      card.style.cursor = "default";
    }

    return card;
  }

  function renderResult(result) {
    const ui = ensureUI();
    const color = COLORS[result.colorKey];

    ui.dot.style.background = color.dot;
    ui.dot.style.boxShadow = `0 0 12px ${color.glow}`;
    ui.score.textContent = `${result.score}%`;
    ui.level.textContent = result.level;
    ui.summary.textContent = `Signals: ${result.signalCount} | Confidence: ${result.confidence}`;
    ui.foot.textContent = `Last scan: ${result.scannedAt}${state.paused ? " | Scanning paused" : ""}`;

    ui.threatList.innerHTML = "";
    if (!result.threatReasons.length) {
      const empty = document.createElement("div");
      empty.className = "ps-empty";
      empty.textContent = "No major scam indicators found.";
      ui.threatList.appendChild(empty);
    } else {
      result.threatReasons.slice(0, 7).forEach((reason) => {
        ui.threatList.appendChild(reasonCard(reason, true));
      });
    }

    ui.mitigationList.innerHTML = "";
    if (!result.mitigationReasons.length) {
      const empty = document.createElement("div");
      empty.className = "ps-empty";
      empty.textContent = "No mitigation adjustment applied.";
      ui.mitigationList.appendChild(empty);
    } else {
      result.mitigationReasons.slice(0, 4).forEach((reason) => {
        ui.mitigationList.appendChild(reasonCard(reason, false));
      });
    }

    if (result.suspiciousHosts.length) {
      const hostCard = document.createElement("div");
      hostCard.className = "ps-empty";
      hostCard.style.marginTop = "6px";
      hostCard.textContent = `Suspicious host(s): ${result.suspiciousHosts.join(", ")}`;
      ui.threatList.appendChild(hostCard);
    }

    if (state.autoHighlightTop && result.threatReasons.length) {
      highlightThreats(result.threatReasons, false);
    }
  }

  function runScan() {
    if (state.paused) return;

    try {
      const result = analyzePage();
      state.result = result;
      renderResult(result);
    } catch (err) {
      const ui = ensureUI();
      ui.summary.textContent = "Scan failed";
      ui.foot.textContent = `Error: ${err && err.message ? err.message : "Unknown"}`;
    }
  }

  function scheduleScan(immediate = false) {
    if (state.scanTimer) {
      clearTimeout(state.scanTimer);
      state.scanTimer = null;
    }

    if (immediate) {
      runScan();
      return;
    }

    state.scanTimer = setTimeout(() => runScan(), RESCAN_DEBOUNCE_MS);
  }

  function startObserver() {
    if (!document.body || state.observer) return;

    state.observer = new MutationObserver(() => {
      if (!state.paused) scheduleScan();
    });

    state.observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true
    });
  }

  function bootstrap() {
    ensureUI();
    runScan();
    startObserver();

    window.addEventListener("load", () => scheduleScan(true));
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) scheduleScan();
    });
  }

  bootstrap();
})();
