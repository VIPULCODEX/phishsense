(function () {
  "use strict";

  const ENABLED_KEY = "phishSenseEnabled";
  const MAX_TEXT_LENGTH = 20000;
  const MAX_LINKS = 250;
  const SCAN_DEBOUNCE_MS = 1400;

  const SHORTENERS = new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "rb.gy",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "goo.gl",
    "shorturl.at"
  ]);

  const SUSPICIOUS_TLDS = new Set([
    "xyz",
    "top",
    "click",
    "work",
    "gq",
    "tk",
    "ml",
    "cf",
    "buzz"
  ]);

  const URGENCY_WORDS = new Set([
    "urgent",
    "immediately",
    "immediate",
    "asap",
    "now",
    "quickly",
    "fast",
    "limited",
    "action",
    "warning",
    "alert"
  ]);

  const PHISHING_WORDS = new Set([
    "verify",
    "verification",
    "account",
    "kyc",
    "login",
    "suspended",
    "blocked",
    "confirm",
    "identity",
    "credentials",
    "bank",
    "debit",
    "upi",
    "pan",
    "password"
  ]);

  const OTP_WORDS = new Set(["otp", "0tp"]);

  const JOB_WORDS = new Set([
    "job",
    "hiring",
    "salary",
    "work",
    "income",
    "earn",
    "registration",
    "offer",
    "selected",
    "amazon",
    "flipkart",
    "fee"
  ]);

  const LOTTERY_WORDS = new Set([
    "lottery",
    "winner",
    "win",
    "prize",
    "jackpot",
    "reward",
    "cashback",
    "bonus",
    "claim",
    "lakh"
  ]);

  const OBFUSCATED_PATTERNS = [
    /\bcl[1i]ck\b/gi,
    /\b0tp\b/gi,
    /\bv[3e]rify\b/gi,
    /\bfr[3e]{2}\b/gi
  ];

  const URL_REGEX = /\b((?:https?:\/\/|www\.)[^\s<>"']+)/gi;

  let isEnabled = true;
  let scanTimer = null;
  let observer = null;

  function tokenize(text) {
    return new Set((text.match(/[a-z0-9]+/g) || []).map((x) => x.toLowerCase()));
  }

  function unique(items) {
    return [...new Set(items)];
  }

  function extractTextUrls(text) {
    return unique((text.match(URL_REGEX) || []).map((u) => u.trim()));
  }

  function getDocumentTextSample() {
    if (!document.body) {
      return "";
    }
    const source = document.body.innerText || "";
    return source.slice(0, MAX_TEXT_LENGTH).toLowerCase();
  }

  function normalizeUrl(raw) {
    try {
      if (!raw) {
        return null;
      }
      const withProtocol = raw.startsWith("http://") || raw.startsWith("https://") ? raw : `https://${raw}`;
      const parsed = new URL(withProtocol);
      return parsed;
    } catch (_) {
      return null;
    }
  }

  function hostLooksRandom(hostname) {
    const clean = hostname.replace(/^www\./, "");
    const root = clean.split(".")[0] || "";
    const hasDigits = /\d/.test(root);
    const longRoot = root.length >= 12;
    const manyHyphens = (root.match(/-/g) || []).length >= 2;
    return (hasDigits && longRoot) || manyHyphens;
  }

  function isIpHost(hostname) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  }

  function domainFromUrl(urlObj) {
    return (urlObj.hostname || "").replace(/^www\./, "").toLowerCase();
  }

  function extractDomLinks() {
    const anchors = Array.from(document.querySelectorAll("a[href]")).slice(0, MAX_LINKS);
    return anchors.map((a) => {
      const href = a.getAttribute("href") || "";
      const text = (a.textContent || "").trim().toLowerCase().slice(0, 120);
      return { href, text };
    });
  }

  function computeRisk() {
    const text = getDocumentTextSample();
    const tokens = tokenize(text);
    const links = extractDomLinks();

    const classScores = {
      phishing: 0,
      otp_scam: 0,
      job_scam: 0,
      lottery: 0,
      safe: 30
    };

    let score = 0;
    const reasons = [];
    const highlightedWords = new Set();
    const suspiciousUrls = [];

    function addReason(points, reason, classBoosts) {
      score += points;
      if (!reasons.includes(reason)) {
        reasons.push(reason);
      }
      if (classBoosts) {
        Object.entries(classBoosts).forEach(([k, v]) => {
          classScores[k] = (classScores[k] || 0) + v;
        });
      }
    }

    function hitWords(pool) {
      return [...tokens].filter((token) => pool.has(token));
    }

    const urgencyHits = hitWords(URGENCY_WORDS);
    if (urgencyHits.length) {
      urgencyHits.forEach((w) => highlightedWords.add(w));
      addReason(14, "Urgency language detected", { phishing: 14 });
    }

    const phishingHits = hitWords(PHISHING_WORDS);
    if (phishingHits.length) {
      phishingHits.forEach((w) => highlightedWords.add(w));
      addReason(20, "Account verification pressure detected", { phishing: 28 });
    }

    const otpHits = hitWords(OTP_WORDS);
    if (otpHits.length) {
      otpHits.forEach((w) => highlightedWords.add(w));
      addReason(30, "OTP collection attempt detected", { otp_scam: 60, phishing: 8 });
    }

    const jobHits = hitWords(JOB_WORDS);
    if (jobHits.length) {
      jobHits.forEach((w) => highlightedWords.add(w));
      addReason(22, "Job or earning lure detected", { job_scam: 55 });
    }

    const lotteryHits = hitWords(LOTTERY_WORDS);
    if (lotteryHits.length) {
      lotteryHits.forEach((w) => highlightedWords.add(w));
      addReason(22, "Prize or lottery lure detected", { lottery: 55 });
    }

    if (tokens.has("fee") && (tokens.has("job") || tokens.has("registration"))) {
      addReason(16, "Advance fee scam pattern detected", { job_scam: 24 });
      highlightedWords.add("fee");
    }

    OBFUSCATED_PATTERNS.forEach((pattern) => {
      const matches = text.match(pattern);
      if (matches && matches.length) {
        addReason(10, "Obfuscated wording detected", { phishing: 10, otp_scam: 6 });
        matches.forEach((m) => highlightedWords.add(m.toLowerCase()));
      }
    });

    const textUrls = extractTextUrls(text);
    const allUrls = new Set(textUrls);
    links.forEach((link) => {
      if (link.href && (link.href.startsWith("http://") || link.href.startsWith("https://") || link.href.startsWith("www."))) {
        allUrls.add(link.href);
      }
    });

    if (allUrls.size) {
      addReason(5, "External links detected", { phishing: 4 });
    }

    allUrls.forEach((rawUrl) => {
      const parsed = normalizeUrl(rawUrl);
      if (!parsed) {
        return;
      }
      const host = domainFromUrl(parsed);
      if (!host) {
        return;
      }

      const tld = host.includes(".") ? host.split(".").pop() : "";
      const isShort = SHORTENERS.has(host);
      const randomHost = hostLooksRandom(host);
      const ipHost = isIpHost(host);
      const punycode = host.includes("xn--");
      const suspiciousTld = tld ? SUSPICIOUS_TLDS.has(tld) : false;

      if (isShort) {
        addReason(20, "Shortened link detected", { phishing: 20 });
        suspiciousUrls.push(rawUrl);
      }
      if (suspiciousTld) {
        addReason(18, "Suspicious domain extension detected", { phishing: 18 });
        suspiciousUrls.push(rawUrl);
      }
      if (randomHost) {
        addReason(14, "Random-looking domain detected", { phishing: 14 });
        suspiciousUrls.push(rawUrl);
      }
      if (ipHost) {
        addReason(20, "IP-based URL detected", { phishing: 20 });
        suspiciousUrls.push(rawUrl);
      }
      if (punycode) {
        addReason(14, "Punycode domain detected", { phishing: 14 });
        suspiciousUrls.push(rawUrl);
      }
    });

    links.forEach((link) => {
      const visibleUrl = (link.text.match(URL_REGEX) || [])[0];
      if (!visibleUrl) {
        return;
      }
      const actual = normalizeUrl(link.href);
      const shown = normalizeUrl(visibleUrl);
      if (!actual || !shown) {
        return;
      }
      const actualHost = domainFromUrl(actual);
      const shownHost = domainFromUrl(shown);
      if (actualHost && shownHost && actualHost !== shownHost) {
        addReason(16, "Deceptive link text mismatch detected", { phishing: 18 });
        suspiciousUrls.push(link.href);
      }
    });

    const hasPasswordInput = !!document.querySelector("input[type='password']");
    if (hasPasswordInput && !location.hostname.endsWith(".gov.in") && !location.hostname.endsWith(".edu")) {
      addReason(6, "Page requests password input", { phishing: 8 });
      highlightedWords.add("password");
    }

    score = Math.max(0, Math.min(100, score));

    let prediction = "safe";
    if (score >= 25) {
      const ordered = Object.entries(classScores)
        .filter(([name]) => name !== "safe")
        .sort((a, b) => b[1] - a[1]);
      prediction = ordered.length ? ordered[0][0] : "phishing";
    }

    if (!reasons.length) {
      reasons.push("No major scam indicators found");
    }

    return {
      prediction,
      riskScore: score,
      reasons: reasons.slice(0, 6),
      highlightedWords: [...highlightedWords].slice(0, 12),
      urlFlag: suspiciousUrls.length > 0 ? "Suspicious" : "Safe",
      suspiciousUrls: unique(suspiciousUrls).slice(0, 5),
      source: "rule_context_hybrid"
    };
  }

  function ensureBadge() {
    let badge = document.getElementById("phish-sense-widget");
    if (badge) {
      return badge;
    }

    badge = document.createElement("div");
    badge.id = "phish-sense-widget";
    badge.style.position = "fixed";
    badge.style.top = "16px";
    badge.style.right = "16px";
    badge.style.zIndex = "2147483647";
    badge.style.width = "300px";
    badge.style.maxWidth = "calc(100vw - 24px)";
    badge.style.background = "#0f172a";
    badge.style.color = "#e2e8f0";
    badge.style.border = "1px solid #334155";
    badge.style.borderRadius = "12px";
    badge.style.fontFamily = "Segoe UI, Arial, sans-serif";
    badge.style.fontSize = "13px";
    badge.style.boxShadow = "0 10px 28px rgba(0,0,0,0.35)";
    badge.style.padding = "10px";
    badge.style.lineHeight = "1.35";
    badge.style.userSelect = "none";

    const header = document.createElement("div");
    header.style.display = "flex";
    header.style.justifyContent = "space-between";
    header.style.alignItems = "center";
    header.style.gap = "8px";

    const title = document.createElement("div");
    title.textContent = "Phish Sense";
    title.style.fontWeight = "700";
    title.style.letterSpacing = "0.2px";

    const riskTag = document.createElement("div");
    riskTag.id = "phish-sense-risk-tag";
    riskTag.style.padding = "2px 8px";
    riskTag.style.borderRadius = "999px";
    riskTag.style.fontSize = "12px";
    riskTag.style.fontWeight = "700";
    riskTag.style.background = "#1e293b";
    riskTag.style.color = "#cbd5e1";

    header.appendChild(title);
    header.appendChild(riskTag);

    const prediction = document.createElement("div");
    prediction.id = "phish-sense-prediction";
    prediction.style.marginTop = "8px";
    prediction.style.fontWeight = "600";

    const reasons = document.createElement("ul");
    reasons.id = "phish-sense-reasons";
    reasons.style.margin = "8px 0 0 16px";
    reasons.style.padding = "0";

    const urls = document.createElement("div");
    urls.id = "phish-sense-urls";
    urls.style.marginTop = "6px";
    urls.style.wordBreak = "break-all";
    urls.style.opacity = "0.9";

    badge.appendChild(header);
    badge.appendChild(prediction);
    badge.appendChild(reasons);
    badge.appendChild(urls);

    document.documentElement.appendChild(badge);
    return badge;
  }

  function updateBadge(result) {
    if (!isEnabled) {
      removeBadge();
      return;
    }

    ensureBadge();

    const riskTag = document.getElementById("phish-sense-risk-tag");
    const prediction = document.getElementById("phish-sense-prediction");
    const reasonsEl = document.getElementById("phish-sense-reasons");
    const urlsEl = document.getElementById("phish-sense-urls");

    if (!riskTag || !prediction || !reasonsEl || !urlsEl) {
      return;
    }

    let tone = "low";
    if (result.riskScore >= 70) {
      tone = "high";
      riskTag.style.background = "#7f1d1d";
      riskTag.style.color = "#fecaca";
    } else if (result.riskScore >= 40) {
      tone = "medium";
      riskTag.style.background = "#78350f";
      riskTag.style.color = "#fde68a";
    } else {
      riskTag.style.background = "#14532d";
      riskTag.style.color = "#bbf7d0";
    }

    riskTag.textContent = `${result.riskScore}% ${tone.toUpperCase()}`;
    prediction.textContent = `Prediction: ${result.prediction} | URL: ${result.urlFlag}`;

    reasonsEl.innerHTML = "";
    result.reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      reasonsEl.appendChild(li);
    });

    if (result.suspiciousUrls.length) {
      urlsEl.textContent = `Suspicious links: ${result.suspiciousUrls.join(" | ")}`;
    } else {
      urlsEl.textContent = "";
    }
  }

  function removeBadge() {
    const badge = document.getElementById("phish-sense-widget");
    if (badge && badge.parentNode) {
      badge.parentNode.removeChild(badge);
    }
  }

  function publishState(result) {
    try {
      chrome.runtime.sendMessage({
        type: "SCAN_RESULT",
        payload: {
          ...result,
          pageUrl: location.href
        }
      });
    } catch (_) {
      // No-op: content script should continue working even if messaging fails.
    }
  }

  function scanNow() {
    if (!isEnabled) {
      return;
    }
    const result = computeRisk();
    updateBadge(result);
    publishState(result);
  }

  function scheduleScan() {
    if (scanTimer) {
      clearTimeout(scanTimer);
    }
    scanTimer = setTimeout(scanNow, SCAN_DEBOUNCE_MS);
  }

  function startObserver() {
    if (!document.body || observer) {
      return;
    }

    observer = new MutationObserver(() => {
      scheduleScan();
    });
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true
    });
  }

  function stopObserver() {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
  }

  function setEnabled(enabled) {
    isEnabled = !!enabled;
    if (isEnabled) {
      scanNow();
      startObserver();
    } else {
      stopObserver();
      removeBadge();
    }
  }

  function bootstrap() {
    chrome.storage.sync.get([ENABLED_KEY], (store) => {
      const enabled = typeof store[ENABLED_KEY] === "boolean" ? store[ENABLED_KEY] : true;
      setEnabled(enabled);
    });

    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === "sync" && Object.prototype.hasOwnProperty.call(changes, ENABLED_KEY)) {
        setEnabled(changes[ENABLED_KEY].newValue);
      }
    });

    window.addEventListener("load", scheduleScan);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) {
        scheduleScan();
      }
    });
  }

  bootstrap();
})();

