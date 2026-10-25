import { beforeEach, describe, expect, it } from "vitest";
import { useSelectionStore } from "@/stores/selection-store";

const s = () => useSelectionStore.getState();
beforeEach(() => s().clear());

describe("selection-store", () => {
  it("starts empty and has a setter per field", () => {
    expect(s()).toMatchObject({ captureId: null, pid: null, location: null, annotationId: null });
    s().setPid(42);
    s().setLocation({ space: "process_va", value: 4096, pid: 42 });
    s().setAnnotationId("a1");
    expect(s()).toMatchObject({ pid: 42, annotationId: "a1", location: { space: "process_va", value: 4096, pid: 42 } });
  });

  it("learning the capture keeps a pid chosen earlier (Image panel before Vol3)", () => {
    s().setPid(5);
    s().setCaptureId("cap-a");
    expect(s().pid).toBe(5);
    expect(s().captureId).toBe("cap-a");
  });

  it("switching to another capture drops pid, location and annotation", () => {
    s().setCaptureId("cap-a");
    s().setPid(5);
    s().setLocation({ space: "physical", value: 1 });
    s().setAnnotationId("x");
    s().setCaptureId("cap-a");
    expect(s().pid).toBe(5);
    s().setCaptureId("cap-b");
    expect(s()).toMatchObject({ captureId: "cap-b", pid: null, location: null, annotationId: null });
  });

  it("clear() resets everything", () => {
    s().setCaptureId("c");
    s().setPid(1);
    s().clear();
    expect(s()).toMatchObject({ captureId: null, pid: null });
  });
});
