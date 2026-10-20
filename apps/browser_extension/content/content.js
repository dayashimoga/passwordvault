/**
 * @file content.js
 * Antigravity Vault - In-Page Content Script
 * Detects login forms, renders secure autofill badges, and safely injects credentials.
 */

(function () {
  "use strict";

  // Anti-Clickjacking & Iframe Isolation: Only run inside the top-level window
  if (window !== window.top) {
    return;
  }

  const BADGE_ATTR = "data-pwdvault-attached";
  const SVG_SHIELD_ICON = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2L3 7V12C3 17.52 6.84 22.74 12 24C17.16 22.74 21 17.52 21 12V7L12 2Z" fill="#00f0ff" fill-opacity="0.2" stroke="#00f0ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M12 8V16M8 12H16" stroke="#00f0ff" stroke-width="2" stroke-linecap="round"/>
    </svg>
  `;

  let activeMenu = null;
  let activeToast = null;
  let lastAutofilledValues = new WeakMap();

  /**
   * Scans document for password and credential input fields.
   */
  function scanAndAttachBadges() {
    const passwordInputs = document.querySelectorAll(`input[type="password"]:not([${BADGE_ATTR}])`);

    passwordInputs.forEach((pwdInput) => {
      // Ignore hidden or miniature dummy fields
      const rect = pwdInput.getBoundingClientRect();
      if (rect.width < 30 || rect.height < 15 || pwdInput.disabled || pwdInput.readOnly) {
        return;
      }

      attachBadge(pwdInput);
    });
  }

  /**
   * Attaches an interactive autofill badge adjacent to a password input.
   */
  function attachBadge(pwdInput) {
    pwdInput.setAttribute(BADGE_ATTR, "true");

    const badge = document.createElement("div");
    badge.className = "pwdvault-input-badge";
    badge.innerHTML = SVG_SHIELD_ICON;
    badge.title = "Antigravity Vault Autofill";
    badge.tabIndex = -1;

    // Position badge over the right end of the input
    positionBadge(badge, pwdInput);

    // Reposition on window resize or scroll
    const updatePosition = () => positionBadge(badge, pwdInput);
    window.addEventListener("resize", updatePosition, { passive: true });
    window.addEventListener("scroll", updatePosition, { passive: true });

    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      toggleLoginsMenu(badge, pwdInput);
    });

    document.body.appendChild(badge);
  }

  /**
   * Calculates dynamic positioning for the badge.
   */
  function positionBadge(badge, input) {
    if (!input.isConnected) {
      badge.remove();
      return;
    }
    const rect = input.getBoundingClientRect();
    const scrollX = window.scrollX || document.documentElement.scrollLeft;
    const scrollY = window.scrollY || document.documentElement.scrollTop;

    badge.style.top = `${rect.top + scrollY + (rect.height - 24) / 2}px`;
    badge.style.left = `${rect.right + scrollX - 30}px`;
  }

  /**
   * Closes any open dropdown menu.
   */
  function closeMenu() {
    if (activeMenu) {
      activeMenu.remove();
      activeMenu = null;
    }
  }

  /**
   * Toggles the logins dropdown menu for the current field.
   */
  async function toggleLoginsMenu(badge, pwdInput) {
    if (activeMenu) {
      closeMenu();
      return;
    }

    const menu = document.createElement("div");
    menu.className = "pwdvault-dropdown-menu";
    menu.innerHTML = `<div class="pwdvault-menu-header"><span class="pwdvault-pulse"></span> Querying Antigravity Vault...</div>`;

    const badgeRect = badge.getBoundingClientRect();
    const scrollX = window.scrollX || document.documentElement.scrollLeft;
    const scrollY = window.scrollY || document.documentElement.scrollTop;

    menu.style.top = `${badgeRect.bottom + scrollY + 6}px`;
    menu.style.left = `${Math.max(10, badgeRect.right + scrollX - 260)}px`;

    document.body.appendChild(menu);
    activeMenu = menu;

    // Query matching logins from background worker
    try {
      const resp = await chrome.runtime.sendMessage({
        action: "GET_LOGINS",
        url: window.location.href
      });

      if (!activeMenu) return;

      if (resp && resp.type === "GetLoginsResponse") {
        renderLoginsMenu(menu, resp.logins, pwdInput);
      } else if (resp && resp.code === 403) {
        menu.innerHTML = `
          <div class="pwdvault-menu-header">Antigravity Vault</div>
          <div class="pwdvault-menu-item pwdvault-disabled">
            <span class="pwdvault-lock-icon">🔒</span> Vault is locked. Open the extension to unlock.
          </div>
        `;
      } else {
        menu.innerHTML = `
          <div class="pwdvault-menu-header">Antigravity Vault</div>
          <div class="pwdvault-menu-item pwdvault-disabled">
            ${resp.error || "No matching credentials"}
          </div>
        `;
      }
    } catch (err) {
      if (activeMenu) {
        menu.innerHTML = `
          <div class="pwdvault-menu-header">Antigravity Vault</div>
          <div class="pwdvault-menu-item pwdvault-disabled">Error: ${err.message}</div>
        `;
      }
    }
  }

  /**
   * Renders logins list into dropdown.
   */
  function renderLoginsMenu(menu, logins, pwdInput) {
    if (!logins || logins.length === 0) {
      menu.innerHTML = `
        <div class="pwdvault-menu-header">Antigravity Vault</div>
        <div class="pwdvault-menu-empty">No saved logins for this domain.</div>
      `;
      return;
    }

    menu.innerHTML = `<div class="pwdvault-menu-header">Matching Credentials (${logins.length})</div>`;

    logins.forEach((login) => {
      const item = document.createElement("div");
      item.className = "pwdvault-menu-item";
      item.innerHTML = `
        <div class="pwdvault-item-title">${escapeHtml(login.title)}</div>
        <div class="pwdvault-item-user">${escapeHtml(login.username || "No username")}</div>
      `;

      item.addEventListener("click", async (e) => {
        e.preventDefault();
        e.stopPropagation();
        closeMenu();
        await executeAutofill(login.id, pwdInput);
      });

      menu.appendChild(item);
    });
  }

  /**
   * Fetches decrypted credentials and safely fills inputs.
   */
  async function executeAutofill(itemId, pwdInput) {
    try {
      const fillResp = await chrome.runtime.sendMessage({
        action: "FILL_CREDENTIAL",
        itemId: itemId,
        url: window.location.href
      });

      if (!fillResp || fillResp.type !== "FillCredentialResponse") {
        console.warn("[PwdVault Content] Autofill failed:", fillResp ? fillResp.error : "Unknown error");
        return;
      }

      const { username, password } = fillResp;
      const form = pwdInput.form || document;

      // Find corresponding username input in the same form or vicinity
      if (username) {
        const userInput = findUsernameInput(form, pwdInput);
        if (userInput) {
          fillFieldValue(userInput, username);
          lastAutofilledValues.set(userInput, username);
        }
      }

      if (password) {
        fillFieldValue(pwdInput, password);
        lastAutofilledValues.set(pwdInput, password);
      }
    } catch (err) {
      console.error("[PwdVault Content] Autofill execution error:", err);
    }
  }

  /**
   * Locates the best matching username or email field for a password input.
   */
  function findUsernameInput(container, pwdInput) {
    const candidates = container.querySelectorAll(
      'input[type="text"], input[type="email"], input:not([type])'
    );

    let bestMatch = null;
    let closestDistance = Infinity;
    const pwdRect = pwdInput.getBoundingClientRect();

    candidates.forEach((cand) => {
      if (cand === pwdInput || cand.disabled || cand.readOnly) return;

      const name = (cand.name || "").toLowerCase();
      const id = (cand.id || "").toLowerCase();
      const autocomplete = (cand.autocomplete || "").toLowerCase();

      // Strong indicators
      if (
        autocomplete.includes("username") ||
        autocomplete.includes("email") ||
        name.includes("user") ||
        name.includes("login") ||
        name.includes("email") ||
        id.includes("user") ||
        id.includes("login") ||
        id.includes("email")
      ) {
        bestMatch = cand;
        return;
      }

      // Proximity fallback: input physically above the password input
      const rect = cand.getBoundingClientRect();
      if (rect.top <= pwdRect.top) {
        const dist = Math.abs(pwdRect.top - rect.bottom);
        if (dist < closestDistance) {
          closestDistance = dist;
          bestMatch = cand;
        }
      }
    });

    return bestMatch;
  }

  /**
   * Safely sets value on input and dispatches framework-compatible synthetic events.
   */
  function fillFieldValue(input, value) {
    input.focus();

    // Use native prototype setter to bypass React/Vue property descriptor overrides
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value"
    )?.set;

    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(input, value);
    } else {
      input.value = value;
    }

    // Dispatch comprehensive set of standard and bubbling synthetic events
    input.dispatchEvent(new Event("input", { bubbles: true, cancelable: true }));
    input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
    input.dispatchEvent(new Event("blur", { bubbles: true, cancelable: true }));
  }

  /**
   * Listens for form submissions to offer saving new credentials.
   */
  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (!form || !(form instanceof HTMLFormElement)) return;

    const pwdInputs = form.querySelectorAll('input[type="password"]');
    if (pwdInputs.length === 0) return;

    const pwdInput = pwdInputs[0];
    const password = pwdInput.value;
    if (!password || password.length < 4) return;

    // If it was just autofilled, do not offer to re-save
    if (lastAutofilledValues.get(pwdInput) === password) return;

    const userInput = findUsernameInput(form, pwdInput);
    const username = userInput ? userInput.value : "";

    showSaveToast(username, password);
  }, true);

  /**
   * Displays an interactive save confirmation toast.
   */
  function showSaveToast(username, password) {
    if (activeToast) activeToast.remove();

    const toast = document.createElement("div");
    toast.className = "pwdvault-save-toast";
    toast.innerHTML = `
      <div class="pwdvault-toast-body">
        <div class="pwdvault-toast-title">Save in Antigravity Vault?</div>
        <div class="pwdvault-toast-sub">${escapeHtml(username || window.location.hostname)}</div>
      </div>
      <div class="pwdvault-toast-actions">
        <button class="pwdvault-btn-primary" id="pwdvault-btn-save">Save</button>
        <button class="pwdvault-btn-secondary" id="pwdvault-btn-dismiss">✕</button>
      </div>
    `;

    document.body.appendChild(toast);
    activeToast = toast;

    toast.querySelector("#pwdvault-btn-save").addEventListener("click", async () => {
      await chrome.runtime.sendMessage({
        action: "SAVE_CREDENTIAL",
        title: document.title || window.location.hostname,
        username: username,
        password: password,
        url: window.location.href
      });
      toast.remove();
      activeToast = null;
    });

    toast.querySelector("#pwdvault-btn-dismiss").addEventListener("click", () => {
      toast.remove();
      activeToast = null;
    });

    // Auto-dismiss after 15 seconds
    setTimeout(() => {
      if (activeToast === toast) {
        toast.remove();
        activeToast = null;
      }
    }, 15000);
  }

  // Close menus on outside click
  document.addEventListener("click", (e) => {
    if (activeMenu && !activeMenu.contains(e.target)) {
      closeMenu();
    }
  });

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Initial scan and dynamic DOM observer for single-page applications
  scanAndAttachBadges();

  const observer = new MutationObserver(() => {
    scanAndAttachBadges();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
})();
