/**
 * @file service_worker.js
 * Antigravity Vault - Browser Extension Background Service Worker
 * Manages Native Messaging communication with the Rust pwdvault-native-host process.
 */

const NATIVE_HOST_NAME = "com.antigravity.pwdvault";
const EXTENSION_ID = "com.antigravity.pwdvault";

// In-memory background state
let currentSessionToken = "";
let currentVaultStatus = "Disconnected";
let nativePort = null;
let pendingCallbacks = new Map();
let messageSequence = 0;

/**
 * Connects to the native messaging host or returns the existing connection.
 */
function getNativePort() {
  if (nativePort) {
    return nativePort;
  }

  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST_NAME);

    nativePort.onMessage.addListener((response) => {
      handleNativeResponse(response);
    });

    nativePort.onDisconnect.addListener(() => {
      const lastError = chrome.runtime.lastError;
      console.warn("[PwdVault Background] Native host disconnected:", lastError ? lastError.message : "closed");
      nativePort = null;
      currentVaultStatus = "Disconnected";
      currentSessionToken = "";

      // Reject all pending promises
      for (const [seq, callback] of pendingCallbacks.entries()) {
        callback({ error: "Native host disconnected", code: 503 });
      }
      pendingCallbacks.clear();
    });

    return nativePort;
  } catch (err) {
    console.error("[PwdVault Background] Failed to connect to native host:", err);
    currentVaultStatus = "Disconnected";
    return null;
  }
}

/**
 * Sends a JSON request to the native messaging host and returns a Promise.
 */
function sendNativeRequest(requestPayload) {
  return new Promise((resolve) => {
    const port = getNativePort();
    if (!port) {
      resolve({ error: "Native host unavailable. Ensure pwdvault-native-host is installed.", code: 503 });
      return;
    }

    const seq = ++messageSequence;
    pendingCallbacks.set(seq, resolve);

    // Timeout after 8 seconds
    setTimeout(() => {
      if (pendingCallbacks.has(seq)) {
        pendingCallbacks.delete(seq);
        resolve({ error: "Native host request timed out", code: 504 });
      }
    }, 8000);

    try {
      port.postMessage(requestPayload);
    } catch (err) {
      pendingCallbacks.delete(seq);
      resolve({ error: err.message, code: 500 });
    }
  });
}

/**
 * Handles incoming responses from the native messaging host.
 */
function handleNativeResponse(response) {
  if (!response) return;

  // Track state changes
  if (response.type === "HandshakeResponse") {
    currentSessionToken = response.session_token || "";
    currentVaultStatus = response.vault_status || "Locked";
  } else if (response.type === "UnlockResponse" && response.success) {
    currentVaultStatus = "Unlocked";
  } else if (response.type === "LockResponse") {
    currentVaultStatus = "Locked";
  } else if (response.type === "StatusResponse") {
    currentVaultStatus = response.status;
  }

  // Resolve earliest pending request
  if (pendingCallbacks.size > 0) {
    const firstKey = pendingCallbacks.keys().next().value;
    const callback = pendingCallbacks.get(firstKey);
    pendingCallbacks.delete(firstKey);
    if (callback) {
      callback(response);
    }
  }
}

/**
 * Initializes handshake with the native host if not already authenticated.
 */
async function ensureHandshake() {
  if (currentSessionToken && currentVaultStatus !== "Disconnected") {
    return { sessionToken: currentSessionToken, status: currentVaultStatus };
  }

  const clientNonce = "ext-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8);
  const resp = await sendNativeRequest({
    type: "Handshake",
    client_nonce: clientNonce,
    extension_id: EXTENSION_ID
  });

  if (resp && resp.type === "HandshakeResponse") {
    currentSessionToken = resp.session_token;
    currentVaultStatus = resp.vault_status;
    return { sessionToken: currentSessionToken, status: currentVaultStatus };
  }

  return { sessionToken: "", status: currentVaultStatus, error: resp.error || "Handshake failed" };
}

// Runtime message listener for popup and content script communication
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      switch (message.action) {
        case "GET_STATUS": {
          await ensureHandshake();
          sendResponse({
            status: currentVaultStatus,
            hasSessionToken: Boolean(currentSessionToken)
          });
          break;
        }

        case "UNLOCK_VAULT": {
          await ensureHandshake();
          const unlockResp = await sendNativeRequest({
            type: "Unlock",
            session_token: currentSessionToken,
            passphrase: message.passphrase,
            vault_path: message.vaultPath || null
          });
          sendResponse(unlockResp);
          break;
        }

        case "LOCK_VAULT": {
          if (!currentSessionToken) {
            sendResponse({ type: "LockResponse", success: true });
            return;
          }
          const lockResp = await sendNativeRequest({
            type: "Lock",
            session_token: currentSessionToken
          });
          currentSessionToken = "";
          currentVaultStatus = "Locked";
          sendResponse(lockResp);
          break;
        }

        case "GET_LOGINS": {
          await ensureHandshake();
          if (currentVaultStatus !== "Unlocked") {
            sendResponse({ type: "ErrorResponse", error: "Vault is locked", code: 403, status: currentVaultStatus });
            return;
          }

          const loginsResp = await sendNativeRequest({
            type: "GetLogins",
            session_token: currentSessionToken,
            url: message.url
          });
          sendResponse(loginsResp);
          break;
        }

        case "FILL_CREDENTIAL": {
          await ensureHandshake();
          if (currentVaultStatus !== "Unlocked") {
            sendResponse({ type: "ErrorResponse", error: "Vault is locked", code: 403 });
            return;
          }

          const fillResp = await sendNativeRequest({
            type: "FillCredential",
            session_token: currentSessionToken,
            item_id: message.itemId,
            url: message.url
          });
          sendResponse(fillResp);
          break;
        }

        case "GENERATE_PASSWORD": {
          const genResp = await sendNativeRequest({
            type: "GeneratePassword",
            length: message.length || 20,
            symbols: message.symbols !== false
          });
          sendResponse(genResp);
          break;
        }

        case "SAVE_CREDENTIAL": {
          await ensureHandshake();
          if (currentVaultStatus !== "Unlocked") {
            sendResponse({ type: "ErrorResponse", error: "Vault is locked", code: 403 });
            return;
          }

          const saveResp = await sendNativeRequest({
            type: "SaveCredential",
            session_token: currentSessionToken,
            title: message.title,
            username: message.username,
            password: message.password,
            url: message.url
          });
          sendResponse(saveResp);
          break;
        }

        default:
          sendResponse({ error: "Unknown action: " + message.action, code: 400 });
      }
    } catch (err) {
      sendResponse({ error: err.message, code: 500 });
    }
  })();

  // Keep channel open for async response
  return true;
});
