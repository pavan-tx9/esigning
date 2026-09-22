import { describe, expect, it, vi } from "vitest";
import { acceptMessage, ParentChannel, parseOriginList } from "@/lib/embed";

const HOST = "https://ehr.example";
const parent = {} as Window;
const init = { type: "esign:init", token: "est_abcdefgh12345678" };

describe("which postMessages are believed", () => {
  it("accepts init from the parent window on an allowed origin", () => {
    const message = acceptMessage({ origin: HOST, source: parent, data: init }, [HOST], parent);
    expect(message).toEqual(init);
  });

  it("rejects an origin that is not on the list, even from the parent", () => {
    const event = { origin: "https://evil.example", source: parent, data: init };
    expect(acceptMessage(event, [HOST], parent)).toBeNull();
  });

  it("rejects look-alike origins: prefix, suffix, scheme and port all matter", () => {
    for (const origin of [
      "https://ehr.example.evil.test",
      "https://evil-ehr.example",
      "http://ehr.example",
      "https://ehr.example:8443",
      "null",
      "",
    ]) {
      expect(acceptMessage({ origin, source: parent, data: init }, [HOST], parent)).toBeNull();
    }
  });

  it("rejects an allowed origin when the sender is not the parent window", () => {
    const sibling = {} as Window;
    expect(acceptMessage({ origin: HOST, source: sibling, data: init }, [HOST], parent)).toBeNull();
    expect(acceptMessage({ origin: HOST, source: null, data: init }, [HOST], parent)).toBeNull();
  });

  it("trusts nobody when there is no parent or no configured origin", () => {
    expect(acceptMessage({ origin: HOST, source: parent, data: init }, [HOST], null)).toBeNull();
    expect(acceptMessage({ origin: HOST, source: parent, data: init }, [], parent)).toBeNull();
  });

  it("rejects malformed messages and tokens that are not session tokens", () => {
    const bad = [
      null,
      "esign:init",
      { type: "esign:init" },
      { type: "esign:init", token: 42 },
      { type: "esign:init", token: "esk_hostkeyhostkey" },
      { type: "esign:init", token: "est_with space" },
      { type: "esign:unknown", token: "est_abcdefgh12345678" },
    ];
    for (const data of bad) {
      expect(acceptMessage({ origin: HOST, source: parent, data }, [HOST], parent)).toBeNull();
    }
  });

  it("keeps a language tag and drops a locale the Signer API would refuse", () => {
    const accept = (data: unknown) =>
      acceptMessage({ origin: HOST, source: parent, data }, [HOST], parent);

    expect(accept({ ...init, locale: "es-MX" })).toEqual({ ...init, locale: "es-MX" });
    expect(accept({ ...init, locale: "en" })).toEqual({ ...init, locale: "en" });
    // A junk locale costs the host its choice of language, never the signer their session.
    for (const locale of ["es MX", "../en", 42, "en_US", "x".repeat(40)]) {
      expect(accept({ ...init, locale })).toEqual(init);
    }
  });

  it("accepts reauth_done under the same rules", () => {
    const data = { type: "esign:reauth_done" };
    expect(acceptMessage({ origin: HOST, source: parent, data }, [HOST], parent)).toEqual(data);
    expect(
      acceptMessage({ origin: "https://x.test", source: parent, data }, [HOST], parent),
    ).toBeNull();
  });
});

describe("the allowed-origin list", () => {
  it("normalises entries and drops wildcards and junk instead of guessing", () => {
    expect(
      parseOriginList(
        "https://a.example/path  https://b.example:8443, *, https://*.c.example nonsense javascript:alert(1)",
      ),
    ).toEqual(["https://a.example", "https://b.example:8443"]);
    expect(parseOriginList(null)).toEqual([]);
  });
});

describe("ParentChannel", () => {
  const event = (origin: string, source: unknown, data: unknown) =>
    ({ origin, source, data }) as MessageEvent;

  it("locks onto the origin that initialised it and only posts there, never to *", () => {
    const other = "https://portal.example";
    const postMessage = vi.fn();
    const fakeParent = { postMessage } as unknown as Window;
    const channel = new ParentChannel([HOST, other], fakeParent);

    channel.post({ type: "esign:ready" });
    expect(postMessage.mock.calls.map((call) => call[1])).toEqual([HOST, other]);

    expect(channel.accept(event(other, fakeParent, init))).not.toBeNull();
    postMessage.mockClear();
    channel.post({ type: "esign:signed" });
    expect(postMessage).toHaveBeenCalledExactlyOnceWith({ type: "esign:signed" }, other);

    // The other allowed origin is no longer listened to for this session.
    expect(channel.accept(event(HOST, fakeParent, { type: "esign:reauth_done" }))).toBeNull();
    expect(channel.accept(event(other, fakeParent, { type: "esign:reauth_done" }))).not.toBeNull();
  });

  it("stays silent when the page is not embedded", () => {
    const channel = new ParentChannel([HOST], null);
    expect(() => channel.post({ type: "esign:ready" })).not.toThrow();
    expect(channel.embedded).toBe(false);
  });
});
