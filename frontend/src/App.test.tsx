import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "@/App";

describe("the scaffold", () => {
  it("renders", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Signing service" })).toBeInTheDocument();
  });

  it("starts without a session token", () => {
    render(<App />);
    expect(screen.getByTestId("token-state")).toHaveTextContent("Waiting for a session token");
  });
});
