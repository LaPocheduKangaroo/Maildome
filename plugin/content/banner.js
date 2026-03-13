/**
 * banner.js — MailDome message display script.
 *
 * Injected into every message display context.  Creates a verdict banner
 * at the top of the email, requests the current state from background.js,
 * and listens for async updates.
 */

"use strict";

// ── Banner DOM ────────────────────────────────────────────────────────────────

const banner = document.createElement("div");
banner.id = "maildome-banner";
banner.setAttribute("role", "status");
banner.setAttribute("aria-live", "polite");

// Insert before any existing content
if (document.body) {
  document.body.insertBefore(banner, document.body.firstChild);
} else {
  document.addEventListener("DOMContentLoaded", () => {
    document.body.insertBefore(banner, document.body.firstChild);
  });
}

// ── Rendering ─────────────────────────────────────────────────────────────────

/**
 * Update the banner DOM to reflect the given state.
 * @param {{ status: string, verdict?: string, score?: number }} state
 */
function renderBanner(state) {
  const display = verdictDisplay(state.status, state.verdict || null);

  // Remove all existing state classes
  banner.className = "";
  banner.classList.add("maildome-banner", display.className);

  const scoreText =
    state.status === "ok" && typeof state.score === "number"
      ? ` (score: ${state.score}/100)`
      : "";

  banner.textContent = display.icon + "  " + display.label + scoreText;
}

// Show "Checking…" immediately
renderBanner({ status: "pending" });

// ── Communication ─────────────────────────────────────────────────────────────

// Ask background for current state (handles the case where background already
// has a result by the time this script loads)
browser.runtime.sendMessage({ type: "GET_VERDICT" }).then(renderBanner).catch(() => {
  // Background script not available — leave "Checking…" banner
});

// Listen for async updates pushed by background.js
browser.runtime.onMessage.addListener((message) => {
  if (message.type === "VERDICT_UPDATE") {
    renderBanner(message);
  }
});
