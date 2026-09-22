/*
 * The host half of the embedding protocol. This is the part a customer writes, so it is the part
 * worth reading.
 *
 * The whole contract:
 *   UI  -> host   esign:ready              the iframe has loaded and wants a token
 *   host -> UI    esign:init {token}       the token, from our backend, over postMessage only
 *   UI  -> host   esign:reauth_required    go and prove who this person is, then tell us
 *   host -> UI    esign:reauth_done        our *backend* has attested it to the service
 *   UI  -> host   esign:signed | esign:sealed | esign:declined | esign:expired
 *   UI  -> host   esign:resize {height}    so the iframe is as tall as its content
 *
 * Three rules keep it safe, and all three are one line each:
 *   - only believe a message whose `source` is our iframe and whose `origin` is the service;
 *   - only post to that same origin, never to "*";
 *   - never put the token anywhere but this postMessage. Not in a URL, not in storage.
 */

(() => {
  const root = document.getElementById("esign");
  const frame = document.getElementById("frame");
  const log = document.getElementById("log");
  const origin = new URL(root.dataset.frameSrc, window.location.href).origin;
  const kiosk = root.dataset.kiosk === "true";
  // Where "back" goes: the worklist, or the signing queue this document was opened from.
  const back = {
    href: root.dataset.returnUrl || "/worklist",
    label: root.dataset.returnLabel || "Back to the worklist",
    testid: "back-link",
  };

  let initialised = false;
  let sessionId = null;
  let signed = false;
  let reportedHeight = 0;

  /*
   * How tall to make the frame. This looks like a detail and is not.
   *
   * The obvious reading of `esign:resize` is "make the frame as tall as its content, so there is
   * no scrollbar inside a scrollbar". Do that and the signing UI never scrolls: its own viewport
   * becomes the whole document, every page of the PDF is on screen as far as the browser is
   * concerned, and "I have looked at every page" is satisfied the moment it loads. The signature
   * would then be evidence that somebody had a document open, not that they read it.
   *
   * So the reported height is a maximum, not an instruction. The frame never grows past the
   * viewport, and the person scrolls through the document inside it, which is what the service
   * then records.
   */
  function sizeFrame(reported) {
    reportedHeight = reported;
    const cap = Math.max(480, Math.round(window.innerHeight * 0.92));
    frame.style.height = `${Math.min(Math.ceil(reported) + 24, cap)}px`;
  }

  window.addEventListener("resize", () => {
    if (reportedHeight > 0) {
      sizeFrame(reportedHeight);
    }
  });

  function note(direction, type, detail) {
    const item = document.createElement("li");
    item.dataset.message = type;
    item.dataset.direction = direction;
    item.textContent = `${direction === "in" ? "service → host" : "host → service"}  ${type}${detail ? "  " + detail : ""}`;
    log.append(item);
  }

  function post(message) {
    frame.contentWindow?.postMessage(message, origin);
    note("out", message.type);
  }

  function outcome(title, detail, actions = []) {
    document.getElementById("outcome-title").textContent = title;
    document.getElementById("outcome-detail").textContent = detail;
    const holder = document.getElementById("outcome-actions");
    holder.replaceChildren();
    for (const action of actions) {
      const link = document.createElement("a");
      link.className = "button";
      link.href = action.href;
      link.textContent = action.label;
      link.dataset.testid = action.testid ?? "";
      holder.append(link);
    }
    document.getElementById("outcome").hidden = false;
  }

  // --------------------------------------------------------------------- the token
  async function sendToken() {
    const response = await fetch(root.dataset.tokenUrl, {
      method: "POST",
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    });
    if (!response.ok) {
      initialised = false;
      outcome("We could not start the signing session", "Go back and open it again.", [back]);
      return;
    }
    const body = await response.json();
    sessionId = body.session_id;
    post({ type: "esign:init", token: body.token, locale: "en-US" });
  }

  // --------------------------------------------------------------------- re-authentication
  const reauthPanel = document.getElementById("reauth");
  const reauthError = document.getElementById("reauth-error");

  function askForPassword() {
    reauthError.hidden = true;
    reauthPanel.hidden = false;
    reauthPanel.scrollIntoView({ block: "center" });
    document.getElementById("reauth-password").focus();
  }

  document.getElementById("reauth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = document.getElementById("reauth-password").value;
    // Our backend does the server-to-server call. The browser never holds the API key, and the
    // signing service only believes a re-authentication that arrives with it.
    const response = await fetch(root.dataset.reauthUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ password, session_id: sessionId }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      reauthError.textContent =
        body.error === "wrong_password"
          ? "That password did not match. Try again."
          : `The records system could not confirm it (${body.error ?? response.status}).`;
      reauthError.hidden = false;
      return;
    }
    document.getElementById("reauth-password").value = "";
    reauthPanel.hidden = true;
    post({ type: "esign:reauth_done" });
  });

  document.getElementById("reauth-cancel").addEventListener("click", () => {
    reauthPanel.hidden = true;
  });

  // --------------------------------------------------------------------- after the signature
  async function watchForFiling() {
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const response = await fetch(root.dataset.statusUrl, { credentials: "same-origin" });
      if (response.ok) {
        const status = await response.json();
        if (status.filed) {
          outcome(
            kiosk ? "Signed, sealed and filed" : "Your signature is recorded",
            "The sealed document arrived by webhook and has been filed in the chart.",
            [{ href: status.document_url, label: "See it in the chart", testid: "filed-link" }, back],
          );
          return;
        }
        if (status.envelope_status === "in_progress") {
          outcome(
            "Signed",
            "The other signers still have to sign. The sealed copy is filed when everyone has.",
            [back],
          );
          return;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    outcome("Signed", "The sealed copy has not arrived yet. It will be filed when it does.", [back]);
  }

  // --------------------------------------------------------------------- messages
  window.addEventListener("message", (event) => {
    if (event.source !== frame.contentWindow || event.origin !== origin) {
      return;
    }
    const data = event.data;
    if (data === null || typeof data !== "object" || typeof data.type !== "string") {
      return;
    }
    if (!data.type.startsWith("esign:")) {
      return;
    }

    if (data.type === "esign:resize") {
      sizeFrame(data.height);
      return;
    }

    note("in", data.type);

    if (data.type === "esign:ready") {
      if (initialised) {
        return;
      }
      initialised = true;
      void sendToken();
      return;
    }
    if (data.type === "esign:reauth_required") {
      if (data.session_id && sessionId && data.session_id !== sessionId) {
        return; // not about the session we started
      }
      askForPassword();
      return;
    }
    if (data.type === "esign:signed") {
      signed = true;
      reauthPanel.hidden = true;
      if (kiosk) {
        outcome("Thank you", "Please hand the tablet back to the front desk.", []);
      }
      void watchForFiling();
      return;
    }
    if (data.type === "esign:declined") {
      outcome(
        "Signed on paper instead",
        kiosk
          ? "Please hand the tablet back to the front desk. The clinic will bring a paper copy."
          : "The clinic has been told, and will bring you a paper copy.",
        kiosk ? [] : [back],
      );
      return;
    }
    if (data.type === "esign:expired" && !signed) {
      outcome("The signing session ended", "Nothing was signed. You can open it again.", [back]);
    }
  });
})();
