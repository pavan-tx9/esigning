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
 *   UI  -> host   esign:next {envelope_id} "I am done with this one; open the next"
 *   UI  -> host   esign:resize {height}    so the iframe is as tall as its content
 *
 * `esign:init` may carry a `queue {index, total, next_title}` when this document is one of a run
 * (Addendum 3 B). The host owns the queue and its tokens; all the UI does with it is show "3 of 8",
 * name what is coming on its Done screen, and ask for it. What "the next one" means is decided
 * here, by our backend, against our list -- never by the frame.
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

  // Which document this frame is on. It changes as a queue advances, so every URL that names a
  // task is built from it rather than read once out of the markup.
  let taskId = root.dataset.taskId;
  let loads = 1;
  const queue =
    root.dataset.queueTotal === undefined
      ? null
      : {
          index: Number(root.dataset.queueIndex),
          total: Number(root.dataset.queueTotal),
          next_title: root.dataset.queueNextTitle || undefined,
        };
  const onTask = (suffix) => `/sign/${encodeURIComponent(taskId)}/${suffix}`;

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
    const response = await fetch(onTask("token"), {
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
    const init = { type: "esign:init", token: body.token, locale: "en-US" };
    if (queue !== null) {
      init.queue = { index: queue.index, total: queue.total };
      if (queue.next_title !== undefined) {
        init.queue.next_title = queue.next_title;
      }
    }
    post(init);
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
    const response = await fetch(onTask("reauth"), {
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
  async function watchForFiling(render = outcome) {
    // The task this started on: a queue may have moved the frame on by the time it answers, and
    // a filing belongs to the document it was asked about.
    const asked = onTask("status");
    for (let attempt = 0; attempt < 40; attempt += 1) {
      const response = await fetch(asked, { credentials: "same-origin" });
      if (response.ok) {
        const status = await response.json();
        if (status.filed) {
          render(
            kiosk ? "Signed, sealed and filed" : "Your signature is recorded",
            "The sealed document arrived by webhook and has been filed in the chart.",
            [{ href: status.document_url, label: "See it in the chart", testid: "filed-link" }, back],
          );
          return;
        }
        if (status.envelope_status === "in_progress") {
          render(
            "Signed",
            "The other signers still have to sign. The sealed copy is filed when everyone has.",
            [back],
          );
          return;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    render("Signed", "The sealed copy has not arrived yet. It will be filed when it does.", [back]);
  }

  // --------------------------------------------------------------------- the run (Addendum 3 B)

  /** The end of a run: every document in it signed, and the list not returned to in between. */
  function finishRun(detail, extra = []) {
    document.getElementById("queue-finished-title").textContent = `All ${queue.total} signed`;
    document.getElementById("queue-finished-detail").textContent = detail;
    const holder = document.getElementById("queue-finished-actions");
    for (const action of extra) {
      const link = document.createElement("a");
      link.className = "button";
      link.href = action.href;
      link.textContent = action.label;
      link.dataset.testid = action.testid ?? "";
      holder.prepend(link);
    }
    document.getElementById("queue-finished").hidden = false;
  }

  /**
   * `esign:next`. The frame is not asking for a document -- it is saying it has finished with
   * this one. Which document comes next is our backend's answer, against our list, for the person
   * whose cookie is on the request; the frame's `envelope_id` is checked there against the
   * envelope we opened, and a mismatch is refused rather than followed.
   */
  async function advance(envelope) {
    const response = await fetch("/queue/next", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ after: taskId, envelope_id: envelope ?? null }),
    });
    if (!response.ok) {
      outcome("We could not open the next document", "Open it from the signing queue instead.", [
        { href: "/queue", label: "Back to the signing queue", testid: "back-link" },
      ]);
      return;
    }
    const body = await response.json();
    if (body.done) {
      finishRun("Every one of them was read, agreed to and signed on its own.");
      return;
    }

    taskId = body.task_id;
    queue.index = body.index;
    queue.total = body.total;
    queue.next_title = body.next_title ?? undefined;
    document.getElementById("doc-title").textContent = body.title;
    document.getElementById("queue-index").textContent = String(body.index);
    frame.title = `Sign ${body.title}`;

    // A new session in the same frame. Reloading it starts the handshake again from
    // `esign:ready`, and the token for the next document is fetched then, as the first one was.
    initialised = false;
    signed = false;
    sessionId = null;
    loads += 1;
    const src = root.dataset.frameSrc;
    frame.src = `${src}${src.includes("?") ? "&" : "?"}n=${loads}`;
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
      if (queue !== null && queue.index < queue.total) {
        // The frame is counting down to the next one. Saying "your signature is recorded" over
        // the top of that, with a link back to the list, would be arguing with it.
        return;
      }
      if (queue !== null) {
        finishRun("Every one of them was read, agreed to and signed on its own.");
        void watchForFiling((title, detail, actions) => finishRun(detail, actions));
        return;
      }
      void watchForFiling();
      return;
    }
    if (data.type === "esign:next") {
      if (queue === null) {
        return; // nothing was said about a queue, so there is no next document to open
      }
      void advance(typeof data.envelope_id === "string" ? data.envelope_id : null);
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
