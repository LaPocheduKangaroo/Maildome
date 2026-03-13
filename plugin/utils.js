/**
 * utils.js — Pure utility functions shared by background and banner scripts.
 *
 * No browser API calls here — all functions are side-effect free so they
 * can be unit-tested in a Node/Jest environment without a browser stub.
 */

"use strict";

/**
 * Map a {status, verdict} state object to display properties.
 *
 * @param {string} status  - "pending" | "ok" | "not_found" | "auth_error" |
 *                           "unreachable" | "not_configured" | "error"
 * @param {string|null} verdict - "CLEAN" | "SUSPICIOUS" | "DANGEROUS" | "PENDING" | null
 * @returns {{ label: string, className: string, icon: string }}
 */
function verdictDisplay(status, verdict) {
  if (status === "ok") {
    switch (verdict) {
      case "CLEAN":
        return {
          label: "MailDome: No threats detected",
          className: "md-clean",
          icon: "✓",
        };
      case "SUSPICIOUS":
        return {
          label: "MailDome: Suspicious — review carefully",
          className: "md-suspicious",
          icon: "⚠",
        };
      case "DANGEROUS":
        return {
          label: "MailDome: DANGEROUS — do not click links or open attachments",
          className: "md-dangerous",
          icon: "✕",
        };
      case "PENDING":
        return {
          label: "MailDome: Analysis in progress…",
          className: "md-pending",
          icon: "⏳",
        };
      default:
        return {
          label: "MailDome: Unknown verdict",
          className: "md-unknown",
          icon: "?",
        };
    }
  }

  switch (status) {
    case "pending":
      return { label: "MailDome: Checking…", className: "md-pending", icon: "⏳" };
    case "not_found":
      return {
        label: "MailDome: Not yet analysed",
        className: "md-unknown",
        icon: "?",
      };
    case "auth_error":
      return {
        label: "MailDome: Authentication error — check extension settings",
        className: "md-error",
        icon: "✕",
      };
    case "unreachable":
      return {
        label: "MailDome: Server unreachable",
        className: "md-error",
        icon: "✕",
      };
    case "not_configured":
      return {
        label: "MailDome: Not configured — click the toolbar button to set up",
        className: "md-unknown",
        icon: "?",
      };
    default:
      return { label: "MailDome: Error", className: "md-error", icon: "✕" };
  }
}

/**
 * Normalise a Thunderbird headerMessageId value to RFC 5322 form
 * (angle brackets included), matching what is stored in the DB.
 *
 * @param {string} raw - value from message.headerMessageId
 * @returns {string}
 */
function normalizeMessageId(raw) {
  const trimmed = (raw || "").trim();
  if (trimmed.startsWith("<") && trimmed.endsWith(">")) {
    return trimmed;
  }
  return "<" + trimmed + ">";
}

/**
 * Build the full MailDome API URL for a Message-ID lookup.
 *
 * @param {string} baseUrl   - e.g. "https://maildome.example.com"
 * @param {string} messageId - normalised message-id (with angle brackets)
 * @returns {string}
 */
function buildApiUrl(baseUrl, messageId) {
  const base = baseUrl.replace(/\/$/, "");
  return base + "/api/v1/emails/by-message-id/" + encodeURIComponent(messageId);
}

// Support both browser extension (no module system) and Node/Jest (CommonJS)
if (typeof module !== "undefined" && module.exports) {
  module.exports = { verdictDisplay, normalizeMessageId, buildApiUrl };
}
