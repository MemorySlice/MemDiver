import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import "@/i18n";
import { ResultsTable } from "@/components/vol3/ResultsTable";
import type { Vol3RunResult } from "@/api/vol3";
import { stubVirtualizerLayout } from "../../helpers/virtualizer";

beforeEach(() => stubVirtualizerLayout(900, 240));

const result = (extra: object) => ({
  plugin: "p", columns: [{ name: "Offset", type: "hex", space: "kernel_va", ...extra }],
  rows: [{ depth: 0, values: [0x1000], absent: {} }], row_count: 1, rows_returned: 1,
} as unknown as Vol3RunResult);

describe("ResultsTable object type badge", () => {
  it("shows object_type next to the space badge", () => {
    render(<ResultsTable result={result({ object_type: "module", object_size: 64 })} overrides={{}}
      onOverride={() => {}} onRowClick={() => {}} />);
    expect(screen.getByTestId("object-type-badge").textContent).toBe("module");
  });

  it("omits it without object_type", () => {
    render(<ResultsTable result={result({})} overrides={{}} onOverride={() => {}} onRowClick={() => {}} />);
    expect(screen.queryByTestId("object-type-badge")).toBeNull();
  });
});
