import { describe, it, expect, beforeEach, vi, type Mock } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { act } from "react";
// See the comment in `ErrorBoundary.test.tsx` -- needed so `tsc -b` sees
// jest-dom's `Assertion` augmentation even though `tests/setup.ts` is
// excluded from that program.
import "@testing-library/jest-dom/vitest";
// Real strings, so every assertion below checks the English the user actually
// sees rather than a key name -- this repo's only guard against a missing key.
import "@/i18n";

vi.mock("@/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/client")>();
  return {
    ...actual,
    listSessions: vi.fn(),
    loadSession: vi.fn(),
    deleteSession: vi.fn(async () => ({ ok: true })),
  };
});

import { deleteSession, listSessions } from "@/api/client";
import type { SessionInfo } from "@/api/types";
import { SessionLanding } from "@/components/landing/SessionLanding";
import { ThemeProvider } from "@/providers/ThemeProvider";
import { RECOVERY_SESSION_NAME } from "@/utils/session-names";

const listSessionsMock = listSessions as unknown as Mock;
const deleteSessionMock = deleteSession as unknown as Mock;

function session(name: string, extra: Partial<SessionInfo> = {}): SessionInfo {
  return {
    path: `/sessions/${name}.json.gz`,
    name,
    display_name: name,
    created_at: "2026-09-14T10:00:00Z",
    mode: "verification",
    input_mode: "single_file",
    input_path: `/dumps/${name}.raw`,
    ...extra,
  };
}

/**
 * The API orders by filename DESCENDING, and "_" (0x5F) sorts below every
 * lowercase letter -- so the recovery entry genuinely arrives last. Reproduce
 * exactly that, or the ordering assertion proves nothing.
 */
const API_ORDER: SessionInfo[] = [
  session("zulu"),
  session("alpha"),
  // `display_name` mirrors `name` because the server derives it from the file
  // stem; `input_path` is a real dump, as it would be for a discarded session.
  session(RECOVERY_SESSION_NAME, {
    display_name: RECOVERY_SESSION_NAME,
    input_path: "/dumps/target.raw",
  }),
];

async function mountLanding(sessions: SessionInfo[] = API_ORDER) {
  listSessionsMock.mockResolvedValue({ sessions });
  const view = render(
    <ThemeProvider>
      <SessionLanding />
    </ThemeProvider>,
  );
  await waitFor(() => expect(listSessionsMock).toHaveBeenCalled());
  await screen.findByText("Recovered work");
  return view;
}

/** Every rendered session card, in DOM order. */
function rows(container: HTMLElement): HTMLElement[] {
  return [...container.querySelectorAll<HTMLElement>(".md-panel")];
}

beforeEach(() => {
  listSessionsMock.mockReset();
  deleteSessionMock.mockReset();
  deleteSessionMock.mockResolvedValue({ ok: true });
});

describe("SessionLanding recovery row", () => {
  it("pins the recovery copy first even though the API returns it last", async () => {
    const { container } = await mountLanding();

    const ordered = rows(container);
    expect(ordered).toHaveLength(3);
    expect(ordered[0]).toBe(screen.getByTestId("recovery-session"));
    // The others keep the order the API gave them.
    expect(ordered[1]).toHaveTextContent("zulu");
    expect(ordered[2]).toHaveTextContent("alpha");
  });

  /**
   * The server has no notion of a reserved name: the file stem IS the
   * session_name IS the display_name it reports back. So the relabelling can
   * only happen at render time -- and if it ever stops happening, the raw
   * "__recovery__" leaks into the UI.
   */
  it("relabels it so the raw reserved name is never shown", async () => {
    const { container } = await mountLanding();

    expect(container.textContent).not.toContain(RECOVERY_SESSION_NAME);
    const recovery = screen.getByTestId("recovery-session");
    expect(recovery).toHaveTextContent("Recovered work");
    expect(recovery).toHaveTextContent("RECOVERED");
    expect(recovery).toHaveTextContent(
      "Saved automatically when you last discarded a session.",
    );
  });

  it("leaves ordinary sessions unmarked", async () => {
    await mountLanding();

    expect(screen.getAllByTestId("recovery-session")).toHaveLength(1);
    expect(screen.getByText("alpha")).toBeInTheDocument();
  });

  it("asks its own delete question -- 'the only copy', not a name", async () => {
    await mountLanding();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);

    await act(async () => {
      screen
        .getByTestId("recovery-session")
        .querySelector<HTMLButtonElement>("button:last-of-type")!
        .click();
    });

    expect(confirm).toHaveBeenCalledWith(
      "Delete the recovered work? This is the only copy.",
    );
    expect(deleteSessionMock).toHaveBeenCalledWith(RECOVERY_SESSION_NAME);
    confirm.mockRestore();
  });

  it("still names ordinary sessions in their delete question", async () => {
    const { container } = await mountLanding();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);

    await act(async () => {
      rows(container)[2]
        .querySelector<HTMLButtonElement>("button:last-of-type")!
        .click();
    });

    expect(confirm).toHaveBeenCalledWith('Delete session "alpha"?');
    // Declined, so nothing was deleted.
    expect(deleteSessionMock).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  it("renders nothing special when there is no recovery copy", async () => {
    listSessionsMock.mockResolvedValue({ sessions: [session("alpha")] });
    const { container } = render(
      <ThemeProvider>
        <SessionLanding />
      </ThemeProvider>,
    );
    await screen.findByText("alpha");

    expect(screen.queryByTestId("recovery-session")).not.toBeInTheDocument();
    expect(rows(container)).toHaveLength(1);
  });
});
