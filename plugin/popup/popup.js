/**
 * popup.js — MailDome extension settings popup.
 *
 * Saves/loads API URL and token from browser.storage.local.
 * Provides a "Test connection" button that hits /api/v1/status.
 */

"use strict";

const urlInput   = document.getElementById("api-url");
const tokenInput = document.getElementById("api-token");
const btnSave    = document.getElementById("btn-save");
const btnTest    = document.getElementById("btn-test");
const statusEl   = document.getElementById("status");

function showStatus(text, type) {
  statusEl.textContent = text;
  statusEl.className = type; // "ok" | "err" | "info"
}

function clearStatus() {
  statusEl.className = "";
  statusEl.textContent = "";
}

// ── Load saved settings ───────────────────────────────────────────────────────

browser.storage.local.get(["apiUrl", "apiToken"]).then(({ apiUrl, apiToken }) => {
  if (apiUrl)   urlInput.value   = apiUrl;
  if (apiToken) tokenInput.value = apiToken;
});

// ── Save ──────────────────────────────────────────────────────────────────────

btnSave.addEventListener("click", async () => {
  const apiUrl   = urlInput.value.trim().replace(/\/$/, "");
  const apiToken = tokenInput.value.trim();

  if (!apiUrl) {
    showStatus("Please enter the server URL.", "err");
    return;
  }
  if (!apiToken) {
    showStatus("Please enter the API token.", "err");
    return;
  }

  await browser.storage.local.set({ apiUrl, apiToken });
  showStatus("Settings saved.", "ok");
});

// ── Test connection ───────────────────────────────────────────────────────────

btnTest.addEventListener("click", async () => {
  const apiUrl   = urlInput.value.trim().replace(/\/$/, "");
  const apiToken = tokenInput.value.trim();

  if (!apiUrl || !apiToken) {
    showStatus("Enter the URL and token first.", "err");
    return;
  }

  showStatus("Testing…", "info");
  btnTest.disabled = true;

  try {
    const resp = await fetch(apiUrl + "/api/v1/status");
    if (resp.ok) {
      const data = await resp.json();
      showStatus(`Connected — server status: ${data.status}`, "ok");
    } else {
      showStatus(`Server returned HTTP ${resp.status}`, "err");
    }
  } catch (err) {
    showStatus(`Could not reach server: ${err.message}`, "err");
  } finally {
    btnTest.disabled = false;
  }
});

urlInput.addEventListener("input",   clearStatus);
tokenInput.addEventListener("input", clearStatus);
