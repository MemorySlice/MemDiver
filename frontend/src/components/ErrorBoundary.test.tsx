import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
// `src/test/setup.ts` already registers these matchers at runtime, but it's
// excluded from the `tsc -b` program (see tsconfig.app.json), so its jest-dom
// type augmentation of `vitest`'s `Assertion` interface never reaches this
// file's type-check. Re-importing here (a no-op extra registration at
// runtime) makes `toBeInTheDocument` etc. type-check too.
import "@testing-library/jest-dom/vitest";
import "@/i18n";
import { ErrorBoundary } from "./ErrorBoundary";

/** Throws on render while `shouldThrow()` returns true; renders normally otherwise. */
function Bomb({ shouldThrow }: { shouldThrow: () => boolean }) {
  if (shouldThrow()) {
    throw new Error("boom");
  }
  return <div>chart content</div>;
}

describe("ErrorBoundary", () => {
  // React logs caught render errors to console.error even though the
  // boundary handles them; that's expected noise for these tests.
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the default fallback with a Retry button on error, and recovers once the child stops throwing", () => {
    const state = { shouldThrow: true };
    render(
      <ErrorBoundary>
        <Bomb shouldThrow={() => state.shouldThrow} />
      </ErrorBoundary>,
    );

    expect(screen.getByText("Something went wrong.")).toBeInTheDocument();
    expect(screen.queryByText("chart content")).not.toBeInTheDocument();

    const retryButton = screen.getByRole("button", { name: "Retry" });
    expect(retryButton).toBeInTheDocument();

    // Simulate the underlying failure being transient: the child no longer
    // throws once we click Retry.
    state.shouldThrow = false;
    fireEvent.click(retryButton);

    expect(screen.getByText("chart content")).toBeInTheDocument();
    expect(screen.queryByText("Something went wrong.")).not.toBeInTheDocument();
  });

  it("calls onReset before clearing its error state, and supports a function fallback with its own retry control", () => {
    const state = { shouldThrow: true };
    let resetCalls = 0;

    render(
      <ErrorBoundary
        onReset={() => {
          resetCalls += 1;
          state.shouldThrow = false;
        }}
        fallback={(retry) => <button onClick={retry}>custom retry</button>}
      >
        <Bomb shouldThrow={() => state.shouldThrow} />
      </ErrorBoundary>,
    );

    const customRetryButton = screen.getByRole("button", { name: "custom retry" });
    fireEvent.click(customRetryButton);

    expect(resetCalls).toBe(1);
    expect(screen.getByText("chart content")).toBeInTheDocument();
  });

  it("keeps rendering a plain-node fallback unchanged (backward compatibility)", () => {
    render(
      <ErrorBoundary fallback={<p>static fallback text</p>}>
        <Bomb shouldThrow={() => true} />
      </ErrorBoundary>,
    );

    expect(screen.getByText("static fallback text")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
