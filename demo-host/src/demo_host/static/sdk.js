/*
 * Demo host: load the signing library into this page and drive it with callbacks instead of
 * postMessage. The session token is fetched from our backend, never put in the URL.
 */
(() => {
  const root = document.getElementById("esign-sdk");
  const mountAt = document.getElementById("esign-root");
  if (root === null || mountAt === null) {
    return;
  }

  const taskId = root.dataset.taskId;
  const api = root.dataset.api;
  const sdkSrc = root.dataset.sdkSrc;
  const sdkCss = root.dataset.sdkCss;
  const back = { href: root.dataset.returnUrl || "/worklist", label: root.dataset.returnLabel || "Back" };

  function outcome(title, detail) {
    document.getElementById("outcome-title").textContent = title;
    document.getElementById("outcome-detail").textContent = detail;
    const holder = document.getElementById("outcome-actions");
    holder.replaceChildren();
    const link = document.createElement("a");
    link.className = "button";
    link.href = back.href;
    link.textContent = back.label;
    link.dataset.testid = "back-link";
    holder.append(link);
    document.getElementById("outcome").hidden = false;
  }

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = src;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error("sdk_unavailable"));
      document.head.append(script);
    });
  }

  function loadStyles(href) {
    if (!href) {
      return;
    }
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = href;
    document.head.append(link);
  }

  async function token() {
    const response = await fetch(`/sign/${encodeURIComponent(taskId)}/token`, {
      method: "POST",
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw new Error("session_missing");
    }
    return response.json();
  }

  async function attest(sessionId) {
    const panel = document.getElementById("reauth");
    const form = document.getElementById("reauth-form");
    const error = document.getElementById("reauth-error");
    panel.hidden = false;
    return new Promise((resolve, reject) => {
      form.onsubmit = async (event) => {
        event.preventDefault();
        error.hidden = true;
        const password = document.getElementById("reauth-password").value;
        const response = await fetch(`/sign/${encodeURIComponent(taskId)}/reauth`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ password, session_id: sessionId }),
        });
        if (!response.ok) {
          error.textContent = "That password was not accepted.";
          error.hidden = false;
          return;
        }
        panel.hidden = true;
        window.dispatchEvent(new Event("esign:reauth_done"));
        resolve();
      };
      document.getElementById("reauth-cancel").onclick = () => {
        panel.hidden = true;
        reject(new Error("cancelled"));
      };
    });
  }

  async function boot() {
    try {
      loadStyles(sdkCss);
      await loadScript(sdkSrc);
      if (typeof window.EsignSdk?.mount !== "function") {
        throw new Error("sdk_unavailable");
      }
      const session = await token();
      window.EsignSdk.mount(mountAt, {
        token: session.token,
        baseUrl: `${api.replace(/\/$/, "")}/v1`,
        onSigned: () => outcome("Signed", "The document has been signed. The sealed copy follows."),
        onSealed: () => outcome("Sealed", "The sealed copy is ready."),
        onDeclined: () => outcome("Declined", "You chose not to sign electronically."),
        onExpired: () => outcome("Expired", "This session ended. Open the document again."),
        onReauthRequired: (sessionId) => {
          void attest(sessionId);
        },
      });
    } catch (error) {
      outcome("We could not start the signing session", "Go back and open it again.");
    }
  }

  void boot();
})();
