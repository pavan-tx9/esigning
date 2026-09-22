/**
 * Dev-only host page. It does what an EHR page does and nothing more: listen for `esign:ready`
 * from its iframe, reply with `esign:init` and a token, and react to the UI's events. The
 * "backend" half of re-authentication is a call into the mock inside the iframe.
 */

import "@/styles.css";
import { SCENARIOS, type Scenario, tokenFor } from "@/mocks/db";

const byId = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const params = new URLSearchParams(window.location.search);
const requested = params.get("scenario") ?? "single";
const scenario: Scenario = requested in SCENARIOS ? (requested as Scenario) : "single";

const frame = byId<HTMLIFrameElement>("frame");
const log = byId<HTMLOListElement>("log");
const reauth = byId<HTMLDivElement>("reauth");
const select = byId<HTMLSelectElement>("scenario");

byId("scenario-name").textContent = scenario;
byId("scenario-detail").textContent = SCENARIOS[scenario];
for (const name of Object.keys(SCENARIOS)) {
  const option = document.createElement("option");
  option.value = name;
  option.textContent = name;
  option.selected = name === scenario;
  select.append(option);
}
select.addEventListener("change", () => {
  params.set("scenario", select.value);
  window.location.search = params.toString();
});

function note(direction: "in" | "out", text: string) {
  const item = document.createElement("li");
  item.textContent = `${direction === "in" ? "UI -> host" : "host -> UI"}  ${text}`;
  item.dataset.message = text;
  log.append(item);
  log.scrollTop = log.scrollHeight;
}

function send(message: Record<string, unknown>) {
  frame.contentWindow?.postMessage(message, window.location.origin);
  note("out", String(message.type));
}

let initialised = false;

window.addEventListener("message", (event) => {
  // The same rules a real host should apply: right frame, right origin.
  if (event.source !== frame.contentWindow || event.origin !== window.location.origin) {
    return;
  }
  const data = event.data as { type?: unknown; height?: unknown };
  if (typeof data?.type !== "string" || !data.type.startsWith("esign:")) {
    return;
  }
  if (data.type === "esign:ready") {
    if (scenario === "no-token" || initialised) {
      return;
    }
    initialised = true;
    note("in", data.type);
    // `?locale=` on the harness stands in for a host that embeds in another language: the UI
    // should ask the API for it and then declare whatever the API actually served.
    send({
      type: "esign:init",
      token: tokenFor(scenario),
      locale: params.get("locale") ?? "en-US",
    });
    return;
  }
  if (data.type === "esign:resize") {
    return;
  }
  note("in", data.type);
  if (data.type === "esign:reauth_required") {
    reauth.hidden = false;
    byId<HTMLButtonElement>("reauth-ok").focus();
  }
});

byId("reauth-ok").addEventListener("click", () => {
  // Host backend: POST /v1/sessions/{id}/reauth. Then the page tells the UI it is done.
  frame.contentWindow?.__esignMock?.attestReauth(scenario);
  reauth.hidden = true;
  send({ type: "esign:reauth_done" });
});
byId("reauth-ignore").addEventListener("click", () => {
  reauth.hidden = true;
});

const latency = params.get("latency");
frame.src = `./sign.html${latency === null ? "" : `?latency=${encodeURIComponent(latency)}`}`;
