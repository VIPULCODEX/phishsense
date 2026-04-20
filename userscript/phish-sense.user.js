// ==UserScript==
// @name         Phish Sense Realtime Scanner
// @namespace    https://github.com/VIPULCODEX/phishsense
// @version      1.1.0
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
  const MAX_TEXT_CHARS = 24000;
  const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "is.gd"]);
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
    "request",
    "documentation",
    "tutorial",
    "example",
    "sample",
    "reference",
    "guide",
    "course",
    "lesson",
    "blog"
  ]);
  const TRUSTED_HOST_HINTS = new Set([
    "github.com",
    "stackoverflow.com",
    "developer.mozilla.org",
    "docs.python.org",
    "wikipedia.org",
    "medium.com"
  ]);

  function tokenize(text) {
    return (text.match(/[a-z0-9]+/g) || []).map((t) => t.toLowerCase());
  }

  function isLikelyTrustedHost(hostname) {
    const host = hostname.replace(/^www\./, "");
    return [...TRUSTED_HOST_HINTS].some((known) => host === known || host.endsWith(`.${known}`));
  }

  function getVisibleText() {
    if (!document.body) {
      return "";
    }

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const chunks = [];
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

      const text = (node.nodeValue || "").replace(/\s+/g, " ").trim();
      if (!text) {
        node = walker.nextNode();
        continue;
      }

      chunks.push(text);
      total += text.length;
      node = walker.nextNode();
    }

    return chunks.join(" ").slice(0, MAX_TEXT_CHARS).toLowerCase();
  }

  function countHits(tokens, set) {
    let count = 0;
    for (const token of tokens) {
      if (set.has(token)) {
        count += 1;
      }
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

  function analyzeUrls(text, tokens) {
    const urls = new Set((text.match(URL_REGEX) || []).map((u) => u.trim()));
    const anchors = Array.from(document.querySelectorAll("a[href]")).slice(0, 250);
    anchors.forEach((a) => urls.add(a.getAttribute("href") || ""));

    let suspiciousUrlCount = 0;
    let mismatchCount = 0;
    const suspiciousHosts = new Set();
    const reasons = [];
    const currentHost = location.hostname.replace(/^www\./, "").toLowerCase();

    urls.forEach((raw) => {
      const parsed = normalize(raw);
      if (!parsed) return;
      const host = parsed.hostname.replace(/^www\./, "").toLowerCase();
      const tld = host.includes(".") ? host.split(".").pop() : "";
      const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
      const isSuspicious =
        SHORTENERS.has(host) || SUSPICIOUS_TLDS.has(tld) || isIp || host.includes("xn--");

      if (isSuspicious) {
        suspiciousUrlCount += 1;
        suspiciousHosts.add(host);
      }

      if (host && host !== currentHost && !isSuspicious) {
        if (tokens.includes("click") || tokens.includes("verify") || tokens.includes("login")) {
          reasons.push("External links with action prompts detected");
        }
      }
    });

    anchors.forEach((a) => {
      const href = a.getAttribute("href") || "";
      const visible = (a.textContent || "").trim();
      if (!href || !visible) return;
      const shownMatch = visible.match(URL_REGEX);
      if (!shownMatch || !shownMatch[0]) return;

      const real = normalize(href);
      const shown = normalize(shownMatch[0]);
      if (!real || !shown) return;

      const realHost = real.hostname.replace(/^www\./, "").toLowerCase();
      const shownHost = shown.hostname.replace(/^www\./, "").toLowerCase();
      if (realHost && shownHost && realHost !== shownHost) {
        mismatchCount += 1;
      }
    });

    if (suspiciousUrlCount > 0) {
      reasons.push(`Suspicious URL patterns in ${suspiciousUrlCount} link(s)`);
    }
    if (mismatchCount > 0) {
      reasons.push(`Mismatched anchor text in ${mismatchCount} link(s)`);
    }

    return {
      urlsCount: urls.size,
      suspiciousUrlCount,
      mismatchCount,
      suspiciousHosts: Array.from(suspiciousHosts).slice(0, 3),
      reasons
    };
  }

  function runScan() {
    const text = getVisibleText();
    const tokens = tokenize(text);
    const tokenSet = new Set(tokens);
    const domain = location.hostname.replace(/^www\./, "").toLowerCase();

    let score = 0;
    const positiveReasons = [];
    const mitigationReasons = [];
    let signalCount = 0;

    function add(points, reason) {
      score += points;
      signalCount += 1;
      if (!positiveReasons.includes(reason)) {
        positiveReasons.push(reason);
      }
    }

    const urgencyHits = countHits(tokens, URGENCY);
    const actionHits = countHits(tokens, ACTION);
    const phishHits = countHits(tokens, PHISH);
    const otpHits = countHits(tokens, OTP);
    const lotteryHits = countHits(tokens, LOTTERY);
    const jobHits = countHits(tokens, JOB);
    const benignHits = countHits(tokens, BENIGN_CONTEXT);
    const moneyMention = /\b(rs|₹|usd|cash|lakh|bonus|reward|prize|salary)\b/i.test(text);
    const obfuscatedHits = (text.match(/\b(cl1ck|0tp|fr33|v3rify)\b/gi) || []).length;

    const urlReport = analyzeUrls(text, tokens);
    const hasPasswordField = !!document.querySelector("input[type='password']");

    if (otpHits > 0 && (actionHits > 0 || urgencyHits > 0)) {
      add(28, `OTP solicitation pattern (${otpHits} hit)`);
    }

    if (phishHits >= 2 && (urgencyHits > 0 || actionHits > 0)) {
      add(20, `Credential/account pressure pattern (${phishHits} hits)`);
    } else if (phishHits >= 3) {
      add(12, `Multiple account-security keywords (${phishHits} hits)`);
    }

    if ((lotteryHits > 0 || jobHits > 0) && (moneyMention || actionHits > 0)) {
      const lureHits = lotteryHits + jobHits;
      add(18, `Financial lure pattern (${lureHits} hits)`);
    }

    if (obfuscatedHits > 0) {
      add(10, `Obfuscated wording detected (${obfuscatedHits} hit)`);
    }

    if (urlReport.suspiciousUrlCount > 0) {
      add(24, urlReport.reasons.find((r) => r.startsWith("Suspicious URL")) || "Suspicious URL pattern detected");
    }

    if (urlReport.mismatchCount > 0) {
      add(18, urlReport.reasons.find((r) => r.startsWith("Mismatched")) || "Link text mismatch detected");
    }

    if (hasPasswordField && (actionHits > 0 || phishHits > 0)) {
      add(10, "Password entry prompt with action language");
    }

    if (urlReport.urlsCount > 0 && (actionHits > 0 || urgencyHits > 0)) {
      score += 3;
      if (!positiveReasons.includes("External links with action language")) {
        positiveReasons.push("External links with action language");
      }
    }

    if (signalCount <= 1) {
      score *= 0.58;
      mitigationReasons.push("Single-signal event; score dampened to reduce false positives");
    }

    if (benignHits >= 5) {
      score -= 15;
      mitigationReasons.push(`Benign content context detected (${benignHits} hits)`);
    } else if (benignHits >= 2) {
      score -= 8;
      mitigationReasons.push(`Some benign context detected (${benignHits} hits)`);
    }

    if (isLikelyTrustedHost(domain)) {
      score -= 10;
      mitigationReasons.push("Trusted host signal applied (not ignored)");
    }

    if (signalCount >= 3 && urlReport.suspiciousUrlCount > 0) {
      score += 6;
      positiveReasons.push("Multi-signal correlation increased confidence");
    }

    score = Math.max(0, Math.min(100, score));
    const level = score >= 72 ? "HIGH RISK" : score >= 42 ? "CAUTION" : "LOW RISK";
    const color = score >= 70 ? "#dc2626" : score >= 40 ? "#d97706" : "#16a34a";
    const confidence = signalCount >= 3 ? "high" : signalCount === 2 ? "medium" : signalCount === 1 ? "low" : "minimal";

    let badge = document.getElementById("phish-sense-userscript");
    if (!badge) {
      badge = document.createElement("div");
      badge.id = "phish-sense-userscript";
      badge.style.position = "fixed";
      badge.style.top = "14px";
      badge.style.right = "14px";
      badge.style.zIndex = "2147483647";
      badge.style.padding = "10px 12px";
      badge.style.background = "#0f172a";
      badge.style.border = "1px solid #334155";
      badge.style.borderRadius = "10px";
      badge.style.color = "#e2e8f0";
      badge.style.font = "12px Segoe UI, Arial, sans-serif";
      badge.style.maxWidth = "300px";
      badge.style.boxShadow = "0 8px 24px rgba(0,0,0,0.35)";
      document.documentElement.appendChild(badge);
    }

    badge.innerHTML = "";
    const title = document.createElement("div");
    title.style.fontWeight = "700";
    title.textContent = `Phish Sense | ${score}%`;
    badge.appendChild(title);

    const levelText = document.createElement("div");
    levelText.style.marginTop = "4px";
    levelText.style.color = color;
    levelText.style.fontWeight = "700";
    levelText.textContent = level;
    badge.appendChild(levelText);

    const signalLine = document.createElement("div");
    signalLine.style.marginTop = "4px";
    signalLine.style.opacity = "0.9";
    signalLine.textContent = `Signals: ${signalCount} | Confidence: ${confidence}`;
    badge.appendChild(signalLine);

    const reasonLine = document.createElement("div");
    reasonLine.style.marginTop = "6px";
    reasonLine.style.lineHeight = "1.4";
    reasonLine.textContent = positiveReasons.length
      ? positiveReasons.slice(0, 3).join(" | ")
      : "No major scam indicators found";
    badge.appendChild(reasonLine);

    if (mitigationReasons.length > 0) {
      const mitigationLine = document.createElement("div");
      mitigationLine.style.marginTop = "4px";
      mitigationLine.style.opacity = "0.82";
      mitigationLine.textContent = `Mitigation: ${mitigationReasons.slice(0, 2).join(" | ")}`;
      badge.appendChild(mitigationLine);
    }

    if (urlReport.suspiciousHosts.length > 0) {
      const hostLine = document.createElement("div");
      hostLine.style.marginTop = "4px";
      hostLine.style.opacity = "0.82";
      hostLine.textContent = `Suspicious host(s): ${urlReport.suspiciousHosts.join(", ")}`;
      badge.appendChild(hostLine);
    }
  }

  runScan();
  const observer = new MutationObserver(() => {
    clearTimeout(window.__phishSenseTimer__);
    window.__phishSenseTimer__ = setTimeout(runScan, 1200);
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  }
})();
