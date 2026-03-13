/**
 * tests/utils.test.js — Jest unit tests for plugin/utils.js
 *
 * Pure function tests: no browser API, no DOM, no network.
 */

"use strict";

const { verdictDisplay, normalizeMessageId, buildApiUrl } = require("../utils");

// ── verdictDisplay ────────────────────────────────────────────────────────────

describe("verdictDisplay — ok status", () => {
  test("CLEAN → green class and check icon", () => {
    const d = verdictDisplay("ok", "CLEAN");
    expect(d.className).toBe("md-clean");
    expect(d.icon).toBe("✓");
    expect(d.label).toMatch(/no threats/i);
  });

  test("SUSPICIOUS → orange class and warning icon", () => {
    const d = verdictDisplay("ok", "SUSPICIOUS");
    expect(d.className).toBe("md-suspicious");
    expect(d.icon).toBe("⚠");
    expect(d.label).toMatch(/suspicious/i);
  });

  test("DANGEROUS → red class and X icon", () => {
    const d = verdictDisplay("ok", "DANGEROUS");
    expect(d.className).toBe("md-dangerous");
    expect(d.icon).toBe("✕");
    expect(d.label).toMatch(/dangerous/i);
  });

  test("PENDING verdict → pending class", () => {
    const d = verdictDisplay("ok", "PENDING");
    expect(d.className).toBe("md-pending");
    expect(d.label).toMatch(/progress/i);
  });

  test("unknown verdict string → unknown class", () => {
    const d = verdictDisplay("ok", "SOMETHING_ELSE");
    expect(d.className).toBe("md-unknown");
  });
});

describe("verdictDisplay — error statuses", () => {
  test("pending status → pending class", () => {
    const d = verdictDisplay("pending", null);
    expect(d.className).toBe("md-pending");
    expect(d.label).toMatch(/checking/i);
  });

  test("not_found → unknown class", () => {
    const d = verdictDisplay("not_found", null);
    expect(d.className).toBe("md-unknown");
    expect(d.label).toMatch(/not yet analysed/i);
  });

  test("auth_error → error class and auth mention", () => {
    const d = verdictDisplay("auth_error", null);
    expect(d.className).toBe("md-error");
    expect(d.label).toMatch(/authentication/i);
  });

  test("unreachable → error class", () => {
    const d = verdictDisplay("unreachable", null);
    expect(d.className).toBe("md-error");
    expect(d.label).toMatch(/unreachable/i);
  });

  test("not_configured → unknown class with setup hint", () => {
    const d = verdictDisplay("not_configured", null);
    expect(d.className).toBe("md-unknown");
    expect(d.label).toMatch(/configured/i);
  });

  test("unknown status → error class", () => {
    const d = verdictDisplay("something_random", null);
    expect(d.className).toBe("md-error");
  });
});

describe("verdictDisplay — return shape", () => {
  test("always returns label, className, icon", () => {
    const statuses = ["ok", "pending", "not_found", "auth_error", "unreachable", "not_configured", "error"];
    const verdicts = ["CLEAN", "SUSPICIOUS", "DANGEROUS", "PENDING", null];
    for (const status of statuses) {
      for (const verdict of verdicts) {
        const d = verdictDisplay(status, verdict);
        expect(typeof d.label).toBe("string");
        expect(typeof d.className).toBe("string");
        expect(typeof d.icon).toBe("string");
        expect(d.label.length).toBeGreaterThan(0);
      }
    }
  });
});

// ── normalizeMessageId ────────────────────────────────────────────────────────

describe("normalizeMessageId", () => {
  test("already-bracketed value is returned unchanged", () => {
    expect(normalizeMessageId("<test@example.com>")).toBe("<test@example.com>");
  });

  test("value without brackets gets wrapped", () => {
    expect(normalizeMessageId("test@example.com")).toBe("<test@example.com>");
  });

  test("leading/trailing whitespace is stripped before wrapping", () => {
    expect(normalizeMessageId("  test@example.com  ")).toBe("<test@example.com>");
  });

  test("empty string produces empty brackets", () => {
    expect(normalizeMessageId("")).toBe("<>");
  });

  test("null/undefined returns empty brackets without throwing", () => {
    expect(normalizeMessageId(null)).toBe("<>");
    expect(normalizeMessageId(undefined)).toBe("<>");
  });
});

// ── buildApiUrl ───────────────────────────────────────────────────────────────

describe("buildApiUrl", () => {
  test("basic construction", () => {
    const url = buildApiUrl("https://maildome.example.com", "<msg@example.com>");
    expect(url).toBe(
      "https://maildome.example.com/api/v1/emails/by-message-id/" +
        encodeURIComponent("<msg@example.com>")
    );
  });

  test("trailing slash on base URL is stripped", () => {
    const url = buildApiUrl("https://maildome.example.com/", "<msg@example.com>");
    expect(url).not.toContain("//api");
    expect(url).toContain("/api/v1/emails/by-message-id/");
  });

  test("angle brackets in message-id are percent-encoded", () => {
    const url = buildApiUrl("https://example.com", "<id@host>");
    expect(url).toContain("%3C");
    expect(url).toContain("%3E");
  });

  test("@ in message-id is percent-encoded", () => {
    const url = buildApiUrl("https://example.com", "<id@host>");
    expect(url).toContain("%40");
  });

  test("different base URLs produce different results", () => {
    const a = buildApiUrl("https://host-a.com", "<x@y>");
    const b = buildApiUrl("https://host-b.com", "<x@y>");
    expect(a).not.toBe(b);
    expect(a).toContain("host-a.com");
    expect(b).toContain("host-b.com");
  });
});
