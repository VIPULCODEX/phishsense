// ==UserScript==
// @name         Phish Sense Realtime Scanner
// @namespace    https://github.com/VIPULCODEX/phishsense
// @version      1.0.0
// @description  Realtime phishing/scam risk scanner for Tampermonkey/Greasemonkey
// @author       VIPULCODEX
// @match        *://*/*
// @run-at       document-idle
// @grant        none
// ==/UserScript==

(function () {
  "use strict";

  const URL_REGEX = /\b((?:https?:\/\/|www\.)[^\s<>"']+)/gi;
  const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "is.gd"]);
  const SUSPICIOUS_TLDS = new Set(["xyz", "top", "click", "work", "gq", "tk", "ml", "cf", "buzz"]);
  const URGENCY = new Set(["urgent", "immediately", "asap", "now", "limited", "alert"]);
  const PHISH = new Set(["verify", "account", "kyc", "login", "confirm", "identity", "password", "bank"]);
  const OTP = new Set(["otp", "0tp"]);
  const LOTTERY = new Set(["lottery", "winner", "prize", "jackpot", "claim", "reward", "bonus"]);
  const JOB = new Set(["job", "hiring", "earn", "income", "salary", "registration", "fee"]);

  function tokenize(text) {
    return new Set((text.match(/[a-z0-9]+/g) || []).map((t) => t.toLowerCase()));
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

  function runScan() {
    const text = (document.body ? document.body.innerText : "").slice(0, 18000).toLowerCase();
    const tokens = tokenize(text);

    let score = 0;
    const reasons = [];

    function add(points, reason) {
      score += points;
      if (!reasons.includes(reason)) {
        reasons.push(reason);
      }
    }

    if ([...tokens].some((t) => URGENCY.has(t))) add(12, "Urgency language detected");
    if ([...tokens].some((t) => PHISH.has(t))) add(18, "Account verification pressure detected");
    if ([...tokens].some((t) => OTP.has(t))) add(26, "OTP collection attempt detected");
    if ([...tokens].some((t) => LOTTERY.has(t))) add(20, "Prize or lottery lure detected");
    if ([...tokens].some((t) => JOB.has(t))) add(20, "Job or earning lure detected");
    if (/\b(cl1ck|0tp|fr33|v3rify)\b/i.test(text)) add(12, "Obfuscated wording detected");

    const urls = new Set((text.match(URL_REGEX) || []).map((u) => u.trim()));
    document.querySelectorAll("a[href]").forEach((a) => urls.add(a.getAttribute("href") || ""));

    let suspicious = false;
    urls.forEach((raw) => {
      const parsed = normalize(raw);
      if (!parsed) return;
      const host = parsed.hostname.replace(/^www\./, "").toLowerCase();
      const tld = host.includes(".") ? host.split(".").pop() : "";
      if (SHORTENERS.has(host) || SUSPICIOUS_TLDS.has(tld) || /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes("xn--")) {
        suspicious = true;
      }
    });

    if (suspicious) add(24, "Suspicious URL found");
    if (urls.size > 0) add(4, "External links detected");

    score = Math.max(0, Math.min(100, score));
    const level = score >= 70 ? "HIGH RISK" : score >= 40 ? "CAUTION" : "LOW RISK";
    const color = score >= 70 ? "#dc2626" : score >= 40 ? "#d97706" : "#16a34a";

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

    const reasonLine = document.createElement("div");
    reasonLine.style.marginTop = "6px";
    reasonLine.style.lineHeight = "1.4";
    reasonLine.textContent = reasons.length ? reasons.slice(0, 3).join(" | ") : "No major scam indicators found";
    badge.appendChild(reasonLine);
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

