const ENABLED_KEY = "phishSenseEnabled";

function tabStateKey(tabId) {
  return `phishSenseTabState:${tabId}`;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get([ENABLED_KEY], (result) => {
    if (typeof result[ENABLED_KEY] !== "boolean") {
      chrome.storage.sync.set({ [ENABLED_KEY]: true });
    }
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== "object") {
    sendResponse({ ok: false, error: "Invalid message." });
    return false;
  }

  if (message.type === "SCAN_RESULT") {
    if (!sender.tab || typeof sender.tab.id !== "number") {
      sendResponse({ ok: false, error: "Missing sender tab id." });
      return false;
    }

    const key = tabStateKey(sender.tab.id);
    const value = {
      ...message.payload,
      timestamp: Date.now()
    };
    chrome.storage.local.set({ [key]: value }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message.type === "GET_ENABLED") {
    chrome.storage.sync.get([ENABLED_KEY], (result) => {
      const enabled = typeof result[ENABLED_KEY] === "boolean" ? result[ENABLED_KEY] : true;
      sendResponse({ ok: true, enabled });
    });
    return true;
  }

  if (message.type === "GET_TAB_STATE") {
    const tabId = message.tabId;
    if (typeof tabId !== "number") {
      sendResponse({ ok: false, error: "Invalid tab id." });
      return false;
    }
    chrome.storage.local.get([tabStateKey(tabId)], (result) => {
      sendResponse({
        ok: true,
        state: result[tabStateKey(tabId)] || null
      });
    });
    return true;
  }

  sendResponse({ ok: false, error: "Unknown message type." });
  return false;
});

