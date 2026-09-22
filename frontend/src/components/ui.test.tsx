import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Button } from "@/components/ui";

/**
 * The flow's blocked actions are all one component. Every step of a signature is reached by
 * pressing a button -- "I have seen every page", "I agree", "sign this document" -- so a button
 * that looks inert and acts anyway is a step taken without the thing it stands for. The call
 * sites used to guard themselves inside their own handlers; this is the guarantee that they no
 * longer have to.
 */
describe("an inert button", () => {
  const user = userEvent.setup();

  it("does not run its action, and says why instead", async () => {
    const act = vi.fn();
    const why = vi.fn();
    render(
      <Button inert onClick={act} onInertClick={why}>
        Continue
      </Button>,
    );
    const button = screen.getByRole("button", { name: "Continue" });

    // Inert, not disabled: a disabled button is skipped by the keyboard and says nothing about
    // what is missing, so it stays reachable and answers when it is pressed.
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).not.toBeDisabled();
    await user.click(button);
    expect(act).not.toHaveBeenCalled();
    expect(why).toHaveBeenCalledTimes(1);
  });

  it("does nothing at all when there is nothing to say", async () => {
    const act = vi.fn();
    render(
      <Button inert onClick={act}>
        Back
      </Button>,
    );
    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(act).not.toHaveBeenCalled();
  });

  it("acts normally once it is no longer inert", async () => {
    const act = vi.fn();
    const why = vi.fn();
    render(
      <Button onClick={act} onInertClick={why}>
        Continue
      </Button>,
    );
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(act).toHaveBeenCalledTimes(1);
    expect(why).not.toHaveBeenCalled();
  });
});

describe("a busy button", () => {
  const user = userEvent.setup();

  it("runs neither the action nor the nudge: the action is already in flight", async () => {
    const act = vi.fn();
    const why = vi.fn();
    render(
      <Button busy onClick={act} onInertClick={why}>
        Signing
      </Button>,
    );
    const button = screen.getByRole("button", { name: /Signing/ });
    expect(button).toHaveAttribute("aria-busy", "true");
    await user.click(button);
    expect(act).not.toHaveBeenCalled();
    expect(why).not.toHaveBeenCalled();
  });
});
