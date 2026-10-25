import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import "@/i18n";

import type { Vol3Requirement } from "@/api/vol3";
import { ArgsForm } from "@/components/vol3/ArgsForm";
import { buildArgs, initialDraft, parseInteger } from "@/components/vol3/vol3-args";

const req = (over: Partial<Vol3Requirement> & { name: string }): Vol3Requirement => ({
  type: "string", requirement: "StringRequirement", description: "", optional: true,
  default: null, ...over,
});
const REQS: Vol3Requirement[] = [
  req({ name: "pid", type: "array", items: { type: "integer" }, requirement: "ListRequirement" }),
  req({ name: "count", type: "integer", default: 5 }),
  req({ name: "name", type: "string", optional: false }),
  req({ name: "dump", type: "boolean", default: false }),
  req({ name: "mode", type: "string", choices: ["fast", "slow"], default: "fast" }),
];

describe("buildArgs", () => {
  it("omits empty optionals so backend defaults and the pid auto-fill apply", () => {
    const { args, errors } = buildArgs(REQS, { ...initialDraft(REQS), name: "x" });
    expect(errors).toEqual({});
    expect(args).toEqual({ count: 5, name: "x", mode: "fast" });
    expect("pid" in args).toBe(false);
  });

  it("parses integer, hex and integer lists", () => {
    const { args } = buildArgs(REQS, { pid: "1, 0x10 3", count: "0x20", name: "n", dump: true, mode: "slow" });
    expect(args).toEqual({ pid: [1, 16, 3], count: 32, name: "n", dump: true, mode: "slow" });
  });

  it("flags a missing required argument and a bad integer", () => {
    const { errors } = buildArgs(REQS, { ...initialDraft(REQS), name: "", count: "abc" });
    expect(errors).toEqual({ name: "required", count: "integer" });
  });

  it("sends an explicit false only when the default is true", () => {
    const on = [req({ name: "flag", type: "boolean", default: true })];
    expect(buildArgs(on, { flag: false }).args).toEqual({ flag: false });
    expect(buildArgs(REQS, { ...initialDraft(REQS), name: "x" }).args).not.toHaveProperty("dump");
  });

  it("rejects non-integers in parseInteger", () => {
    expect(parseInteger("12")).toBe(12);
    expect(parseInteger("0xff")).toBe(255);
    expect(parseInteger("1.5")).toBeNull();
    expect(parseInteger("")).toBeNull();
  });
});

describe("ArgsForm", () => {
  it("renders one control per type and reports edits", () => {
    const onChange = vi.fn();
    render(<ArgsForm requirements={REQS} draft={initialDraft(REQS)} errors={{ name: "required" }}
      onChange={onChange} pidAutoFill="pid" />);
    expect(screen.getByLabelText(/^pid/).getAttribute("type")).toBe("text");
    expect(screen.getByLabelText(/^dump/).getAttribute("type")).toBe("checkbox");
    expect(screen.getByLabelText(/^mode/).tagName).toBe("SELECT");
    expect(screen.getByTestId("pid-autofill-hint")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("required");
    expect(screen.getByTestId("arg-name")).toHaveTextContent("required");
    expect(screen.getByTestId("arg-pid")).toHaveTextContent("optional");
    fireEvent.click(screen.getByLabelText(/^dump/));
    expect(onChange).toHaveBeenCalledWith("dump", true);
    fireEvent.change(screen.getByLabelText(/^count/), { target: { value: "9" } });
    expect(onChange).toHaveBeenCalledWith("count", "9");
  });

  it("says so when a plugin takes no arguments", () => {
    render(<ArgsForm requirements={[]} draft={{}} errors={{}} onChange={vi.fn()} pidAutoFill={null} />);
    expect(screen.getByTestId("args-none")).toBeInTheDocument();
  });
});
