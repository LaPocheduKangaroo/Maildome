/**
 * background.js — MailDome Thunderbird extension background script.
 *
 * Listens for message display events, queries the MailDome API for the
 * verdict, and forwards the result to the banner content script.
 *
 * State is kept in a per-tab Map.  When banner.js loads it requests the
 * current state synchronously; async updates are pushed via sendMessage.
 */

"use strict";

// In-memory state: tabId → verdict state object
const tabState = new Map();

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Notify the banner script in a tab, ignoring errors when tab is gone. */
async function notifyTab(tabId, state) {
  try {
    await browser.tabs.sendMessage(tabId, { type: "VERDICT_UPDATE", ...state });
  } catch (_) {
    // Tab closed or content script not yet ready — silently ignore
  }
}

/** Fetch verdict from MailDome API and update tabState. */
async function fetchVerdict(tabId, messageId) {
  const { apiUrl, apiToken } = await browser.storage.local.get([
    "apiUrl",
    "apiToken",
  ]);

  if (!apiUrl || !apiToken) {
    const state = { status: "not_configured" };
    tabState.set(tabId, state);
    await notifyTab(tabId, state);
    return;
  }

  const normId = normalizeMessageId(messageId);
  const url = buildApiUrl(apiUrl, normId);

  let state;
  try {
    const resp = await fetch(url, {
      headers: { Authorization: "Bearer " + apiToken },
    });

    if (resp.status === 404) {
      state = { status: "not_found" };
    } else if (resp.status === 401 || resp.status === 403) {
      state = { status: "auth_error" };
    } else if (!resp.ok) {
      state = { status: "error", detail: resp.statusText };
    } else {
      const data = await resp.json();
      state = {
        status: "ok",
        verdict: data.verdict,
        score: data.score,
      };
    }
  } catch (err) {
    state = { status: "unreachable" };
  }

  tabState.set(tabId, state);
  await notifyTab(tabId, state);
}

// ── Event listeners ───────────────────────────────────────────────────────────

/** When a message is displayed: set pending state, start API query. */
browser.messageDisplay.onMessageDisplayed.addListener((tab, message) => {
  const pending = { status: "pending" };
  tabState.set(tab.id, pending);
  // Don't await — let the banner show "Checking…" immediately
  fetchVerdict(tab.id, message.headerMessageId);
});

/** Clean up state when a tab is closed. */
browser.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

/** Handle synchronous state requests from banner.js. */
browser.runtime.onMessage.addListener((message, sender) => {
  if (message.type === "GET_VERDICT" && sender.tab) {
    const state = tabState.get(sender.tab.id) || { status: "pending" };
    return Promise.resolve(state);
  }
});
