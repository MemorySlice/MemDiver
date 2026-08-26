import { describe, it, expect } from "vitest";
import { lazy, Suspense } from "react";
import { render, screen } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx` — needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
import "@/i18n";
import { ChartSkeleton } from "@/components/charts/ChartSkeleton";

describe("ChartSkeleton", () => {
  it("renders a status placeholder with an accessible loading message", () => {
    render(<ChartSkeleton />);

    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(screen.getByText("Loading chart…")).toBeInTheDocument();
  });

  it("shows while acting as the Suspense fallback for a still-pending lazy import", () => {
    // A dynamic import whose promise never resolves within the test —
    // mirrors the real dispatcher's `<Suspense fallback={<ChartSkeleton />}>`
    // during the window before a lazy chart chunk finishes loading.
    const NeverResolves = lazy(() => new Promise<{ default: () => null }>(() => {}));

    render(
      <Suspense fallback={<ChartSkeleton />}>
        <NeverResolves />
      </Suspense>,
    );

    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(screen.getByText("Loading chart…")).toBeInTheDocument();
  });
});
