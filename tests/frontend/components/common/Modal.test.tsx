import { useRef, useState } from "react";
import { describe, it, expect, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
// See the comment in `ErrorBoundary.test.tsx` -- needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
// Real strings, so every assertion below checks the English the user actually
// sees rather than a key name.
import "@/i18n";

import { Modal } from "@/components/common/Modal";

function renderModal(props: Partial<React.ComponentProps<typeof Modal>> = {}) {
  const onClose = props.onClose ?? vi.fn();
  render(
    <Modal title="Start a new session?" onClose={onClose} {...props}>
      <button data-testid="body-button">body</button>
    </Modal>,
  );
  return { onClose };
}

describe("Modal", () => {
  it("exposes itself as a labelled modal dialog", () => {
    renderModal();

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    // The accessible name comes from the heading via aria-labelledby.
    expect(dialog).toHaveAccessibleName("Start a new session?");
  });

  it("focuses the close button on open by default", () => {
    renderModal();

    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();
  });

  it("honours initialFocusRef so the safe control gets focus", () => {
    function Harness() {
      const ref = useRef<HTMLInputElement>(null);
      return (
        <Modal title="t" onClose={vi.fn()} initialFocusRef={ref}>
          <input ref={ref} data-testid="named" />
        </Modal>
      );
    }
    render(<Harness />);

    expect(screen.getByTestId("named")).toHaveFocus();
  });

  it("restores focus to whatever opened it", () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>opener</button>
          {open && (
            <Modal title="t" onClose={() => setOpen(false)}>
              <span>body</span>
            </Modal>
          )}
        </>
      );
    }
    render(<Harness />);

    const opener = screen.getByRole("button", { name: "opener" });
    opener.focus();
    fireEvent.click(opener);
    fireEvent.click(screen.getByRole("button", { name: "Close" }));

    expect(opener).toHaveFocus();
  });

  it("closes on Escape from anywhere, not just from inside the dialog", () => {
    const { onClose } = renderModal();

    // Escape is listened for on `document` on purpose: a backdrop click moves
    // focus to <body>, and someone who lands there still expects it to work.
    fireEvent.keyDown(document, { key: "Escape" });

    expect(onClose).toHaveBeenCalled();
  });

  it("closes on a backdrop click but not on a click inside the panel", () => {
    const { onClose } = renderModal();

    fireEvent.click(screen.getByTestId("body-button"));
    expect(onClose).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId("modal-overlay"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("ignores the backdrop when the choice must be deliberate", () => {
    const { onClose } = renderModal({ closeOnBackdrop: false });

    fireEvent.click(screen.getByTestId("modal-overlay"));

    expect(onClose).not.toHaveBeenCalled();
  });

  it("cycles focus within the dialog rather than escaping to the page", () => {
    render(
      <Modal
        title="t"
        onClose={vi.fn()}
        footer={<button data-testid="last">confirm</button>}
      >
        <button data-testid="middle">middle</button>
      </Modal>,
    );

    const overlay = screen.getByTestId("modal-overlay");
    const close = screen.getByRole("button", { name: "Close" });
    const last = screen.getByTestId("last");

    // Forward off the last tabbable wraps to the first.
    last.focus();
    fireEvent.keyDown(overlay, { key: "Tab" });
    expect(close).toHaveFocus();

    // Backward off the first wraps to the last.
    fireEvent.keyDown(overlay, { key: "Tab", shiftKey: true });
    expect(last).toHaveFocus();
  });

  it("leaves focus alone mid-cycle so normal tabbing still works", () => {
    render(
      <Modal title="t" onClose={vi.fn()} footer={<button data-testid="last">go</button>}>
        <button data-testid="middle">middle</button>
      </Modal>,
    );

    const middle = screen.getByTestId("middle");
    middle.focus();
    fireEvent.keyDown(screen.getByTestId("modal-overlay"), { key: "Tab" });

    // Not first and not last: the browser's own tab order handles it.
    expect(middle).toHaveFocus();
  });

  it("omits the footer row entirely when there are no actions", () => {
    renderModal();

    expect(screen.queryByTestId("last")).not.toBeInTheDocument();
  });
});
