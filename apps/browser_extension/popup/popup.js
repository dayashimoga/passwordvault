/**
 * @file popup.js
 * Antigravity Vault - Browser Extension Popup Controller
 */

let currentTab = null;
let currentUrl = "";
let currentHostname = "";

// DOM Elements
const statusPill = document.getElementById("status-pill");
const btnLock = document.getElementById("btn-lock");
const domainHost = document.getElementById("domain-host");
const errorBanner = document.getElementById("error-banner");

const viewLocked = document.getElementById("view-locked");
const viewUnlocked = document.getElementById("view-unlocked");
const viewDisconnected = document.getElementById("view-disconnected");

const formUnlock = document.getElementById("form-unlock");
const inputPassphrase = document.getElementById("input-passphrase");

const btnTabLogins = document.getElementById("btn-tab-logins");
const btnTabGenerator = document.getElementById("btn-tab-generator");
const tabLogins = document.getElementById("tab-logins");
const tabGenerator = document.getElementById("tab-generator");
const loginsList = document.getElementById("logins-list");
const btnSaveCurrent = document.getElementById("btn-save-current");

const genPasswordEl = document.getElementById("gen-password");
const btnCopyGen = document.getElementById("btn-copy-gen");
const sliderLength = document.getElementById("slider-length");
const sliderLengthVal = document.getElementById("slider-length-val");
const chkSymbols = document.getElementById("chk-symbols");
const btnRegenerate = document.getElementById("btn-regenerate");
const entropyFill = document.getElementById("entropy-fill");
const entropyLabel = document.getElementById("entropy-label");
const btnRetry = document.getElementById("btn-retry-connection");

/**
 * Initializes the popup view.
 */
async function init() {
  await detectActiveTab();
  setupEventListeners();
  await refreshVaultStatus();
}

/**
 * Detects current active tab URL and domain.
 */
async function detectActiveTab() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs.length > 0) {
      currentTab = tabs[0];
      currentUrl = currentTab.url || "";
      try {
        const parsed = new URL(currentUrl);
        currentHostname = parsed.hostname;
        domainHost.textContent = currentHostname || "Internal Page";
      } catch {
        currentHostname = "";
        domainHost.textContent = "Browser Page";
      }
    }
  } catch (err) {
    console.warn("Could not query active tab:", err);
  }
}

/**
 * Updates UI status pill and toggles view panels.
 */
function updateStatus(status) {
  statusPill.className = "status-pill";
  hideError();

  if (status === "Unlocked") {
    statusPill.classList.add("status-unlocked");
    statusPill.textContent = "Unlocked";
    btnLock.style.display = "flex";

    viewLocked.style.display = "none";
    viewDisconnected.style.display = "none";
    viewUnlocked.style.display = "flex";
  } else if (status === "Locked") {
    statusPill.classList.add("status-locked");
    statusPill.textContent = "Locked";
    btnLock.style.display = "none";

    viewUnlocked.style.display = "none";
    viewDisconnected.style.display = "none";
    viewLocked.style.display = "flex";
    inputPassphrase.focus();
  } else {
    statusPill.classList.add("status-disconnected");
    statusPill.textContent = "Disconnected";
    btnLock.style.display = "none";

    viewUnlocked.style.display = "none";
    viewLocked.style.display = "none";
    viewDisconnected.style.display = "flex";
  }
}

/**
 * Queries vault status from service worker.
 */
async function refreshVaultStatus() {
  try {
    const resp = await chrome.runtime.sendMessage({ action: "GET_STATUS" });
    if (resp && resp.status) {
      updateStatus(resp.status);
      if (resp.status === "Unlocked") {
        await loadLoginsForCurrentSite();
      }
    } else {
      updateStatus("Disconnected");
    }
  } catch (err) {
    updateStatus("Disconnected");
  }
}

/**
 * Fetches matching logins for current tab.
 */
async function loadLoginsForCurrentSite() {
  if (!currentUrl || !currentUrl.startsWith("http")) {
    loginsList.innerHTML = `<div class="empty-state">Autofill only active on http/https web pages.</div>`;
    return;
  }

  loginsList.innerHTML = `<div class="loading-state">Querying matching credentials...</div>`;

  try {
    const resp = await chrome.runtime.sendMessage({
      action: "GET_LOGINS",
      url: currentUrl
    });

    if (resp && resp.type === "GetLoginsResponse") {
      renderLogins(resp.logins);
    } else {
      showError(resp.error || "Failed to load logins");
      loginsList.innerHTML = `<div class="empty-state">Error querying logins.</div>`;
    }
  } catch (err) {
    showError(err.message);
    loginsList.innerHTML = `<div class="empty-state">Failed to query credentials.</div>`;
  }
}

/**
 * Renders login cards.
 */
function renderLogins(logins) {
  if (!logins || logins.length === 0) {
    loginsList.innerHTML = `
      <div class="empty-state">
        No credentials saved for <strong>${escapeHtml(currentHostname)}</strong>.
      </div>
    `;
    return;
  }

  loginsList.innerHTML = "";
  logins.forEach((login) => {
    const card = document.createElement("div");
    card.className = "login-card";
    card.innerHTML = `
      <div class="login-info">
        <span class="login-title">${escapeHtml(login.title)}</span>
        <span class="login-username">${escapeHtml(login.username || "No username")}</span>
      </div>
      <div class="login-actions">
        <button class="btn-autofill" data-id="${login.id}" title="Autofill into current page">Autofill</button>
        <button class="btn-copy btn-copy-pwd" data-id="${login.id}" title="Copy Password">PWD</button>
      </div>
    `;

    // Autofill event
    card.querySelector(".btn-autofill").addEventListener("click", async () => {
      await fillCredentialIntoTab(login.id);
    });

    // Copy password event
    card.querySelector(".btn-copy-pwd").addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      await copyPasswordForId(login.id, btn);
    });

    loginsList.appendChild(card);
  });
}

/**
 * Fills credential into current web page via native host and content script.
 */
async function fillCredentialIntoTab(itemId) {
  try {
    const fillResp = await chrome.runtime.sendMessage({
      action: "FILL_CREDENTIAL",
      itemId: itemId,
      url: currentUrl
    });

    if (!fillResp || fillResp.type !== "FillCredentialResponse") {
      showError(fillResp ? fillResp.error : "Failed to retrieve credential");
      return;
    }

    // Execute autofill script directly into current tab
    if (currentTab && currentTab.id) {
      await chrome.scripting.executeScript({
        target: { tabId: currentTab.id },
        func: (username, password) => {
          const pwdInputs = document.querySelectorAll('input[type="password"]');
          if (pwdInputs.length > 0) {
            const pwdInput = pwdInputs[0];
            const form = pwdInput.form || document;

            // Find username field
            const userInput = form.querySelector(
              'input[type="text"], input[type="email"], input[autocomplete*="username"]'
            );

            const setValue = (el, val) => {
              el.focus();
              const nativeSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype,
                "value"
              )?.set;
              if (nativeSetter) {
                nativeSetter.call(el, val);
              } else {
                el.value = val;
              }
              el.dispatchEvent(new Event("input", { bubbles: true }));
              el.dispatchEvent(new Event("change", { bubbles: true }));
            };

            if (userInput && username) setValue(userInput, username);
            if (password) setValue(pwdInput, password);
          }
        },
        args: [fillResp.username || "", fillResp.password || ""]
      });

      window.close(); // Close popup upon successful autofill
    }
  } catch (err) {
    showError("Autofill failed: " + err.message);
  }
}

/**
 * Copies password for an item to clipboard.
 */
async function copyPasswordForId(itemId, btn) {
  try {
    const fillResp = await chrome.runtime.sendMessage({
      action: "FILL_CREDENTIAL",
      itemId: itemId,
      url: currentUrl
    });

    if (fillResp && fillResp.password) {
      await navigator.clipboard.writeText(fillResp.password);
      const originalText = btn.textContent;
      btn.textContent = "✓";
      btn.style.color = "var(--success)";
      setTimeout(() => {
        btn.textContent = originalText;
        btn.style.color = "";
      }, 1500);
    }
  } catch (err) {
    showError("Copy failed: " + err.message);
  }
}

/**
 * Generates a new password via Rust native host.
 */
async function generateNewPassword() {
  const length = parseInt(sliderLength.value, 10);
  const symbols = chkSymbols.checked;

  try {
    const resp = await chrome.runtime.sendMessage({
      action: "GENERATE_PASSWORD",
      length: length,
      symbols: symbols
    });

    if (resp && resp.type === "GeneratePasswordResponse") {
      genPasswordEl.textContent = resp.password;
      const bits = Math.round(resp.entropy_bits);
      entropyLabel.textContent = `Entropy: ~${bits} bits (${resp.rating})`;
      const pct = Math.min(100, Math.max(20, (bits / 128) * 100));
      entropyFill.style.width = `${pct}%`;
    }
  } catch (err) {
    genPasswordEl.textContent = "Error generating";
  }
}

/**
 * Wires up form and button interactions.
 */
function setupEventListeners() {
  // Unlock Form
  formUnlock.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideError();
    const passphrase = inputPassphrase.value;
    if (!passphrase) return;

    try {
      const resp = await chrome.runtime.sendMessage({
        action: "UNLOCK_VAULT",
        passphrase: passphrase
      });

      if (resp && resp.type === "UnlockResponse" && resp.success) {
        inputPassphrase.value = "";
        updateStatus("Unlocked");
        await loadLoginsForCurrentSite();
      } else {
        showError(resp ? resp.error || "Invalid master passphrase" : "Unlock failed");
      }
    } catch (err) {
      showError("Unlock error: " + err.message);
    }
  });

  // Lock Button
  btnLock.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ action: "LOCK_VAULT" });
    updateStatus("Locked");
  });

  // Tab switching
  btnTabLogins.addEventListener("click", () => {
    btnTabLogins.classList.add("active");
    btnTabGenerator.classList.remove("active");
    tabLogins.classList.add("active");
    tabGenerator.classList.remove("active");
  });

  btnTabGenerator.addEventListener("click", () => {
    btnTabGenerator.classList.add("active");
    btnTabLogins.classList.remove("active");
    tabGenerator.classList.add("active");
    tabLogins.classList.remove("active");
    generateNewPassword();
  });

  // Generator inputs
  sliderLength.addEventListener("input", () => {
    sliderLengthVal.textContent = sliderLength.value;
    generateNewPassword();
  });

  chkSymbols.addEventListener("change", () => {
    generateNewPassword();
  });

  btnRegenerate.addEventListener("click", () => {
    generateNewPassword();
  });

  // Copy generated password
  btnCopyGen.addEventListener("click", async () => {
    const pw = genPasswordEl.textContent;
    if (pw && pw !== "Generating...") {
      await navigator.clipboard.writeText(pw);
      btnCopyGen.style.color = "var(--success)";
      setTimeout(() => {
        btnCopyGen.style.color = "";
      }, 1500);
    }
  });

  // Save current credential prompt
  btnSaveCurrent.addEventListener("click", async () => {
    const username = prompt("Enter username or email for " + currentHostname + ":");
    if (!username) return;
    const password = prompt("Enter password:");
    if (!password) return;

    const resp = await chrome.runtime.sendMessage({
      action: "SAVE_CREDENTIAL",
      title: currentHostname,
      username: username,
      password: password,
      url: currentUrl
    });

    if (resp && resp.type === "SaveCredentialResponse" && resp.success) {
      await loadLoginsForCurrentSite();
    } else {
      showError(resp ? resp.error : "Failed to save credential");
    }
  });

  btnRetry.addEventListener("click", async () => {
    await refreshVaultStatus();
  });
}

function showError(msg) {
  errorBanner.textContent = msg;
  errorBanner.style.display = "block";
}

function hideError() {
  errorBanner.textContent = "";
  errorBanner.style.display = "none";
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

document.addEventListener("DOMContentLoaded", init);
