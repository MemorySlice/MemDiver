import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// React Testing Library auto-registers its `afterEach(cleanup)` only when it
// detects a global `afterEach` (e.g. Jest, or vitest with `test.globals:
// true`). This project imports test functions explicitly from "vitest"
// instead of using globals, so that detection never fires and every
// `render()` from a previous test would otherwise leak into the next one.
// Register it explicitly so DOM-rendering tests are isolated from each other.
afterEach(() => {
  cleanup();
});
