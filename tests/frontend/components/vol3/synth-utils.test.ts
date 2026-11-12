import { describe, expect, it } from "vitest";

import {
  buildSynthRequest, cellText, defaultPluginName, execColumns, execRequestForVerdict, execRequestFromVolCommand,
  isHexSecret, isProvenCell, isSecretColumn, maskSecret, shellSplit, validateDraft, withoutMemdiverDir,
  type SynthDraft,
} from "@/components/vol3/synth-utils";
import {
  CASE_PLUGINS, CIPHER2, EXEC, KEY1, KEY2, PLUGIN, REPO_PLUGINS, RUN1, RUN2, SYNTH,
} from "./synth-fixtures";

const draft = (patch: Partial<SynthDraft> = {}): SynthDraft => ({
  dumps: [{ path: RUN1, secretHex: KEY1, samplePath: "/data/run_0001/cipher" }],
  name: "memdiver_gocryptfs", oracleKind: "gocryptfs-gcm", caseDir: "my-case", context: "64",
  verifyOnMsl: true, allowHighEntropy: false, fullImage: "", pid: "", fullImageSample: "",
  fullImageSecretHex: "", symbolDirs: "", ...patch,
});

describe("secret handling", () => {
  it("masks a key to its length only: no byte of it, not even the ends", () => {
    const masked = maskSecret(KEY1);
    expect(masked).toBe("•••• (32 B)");
    expect(masked).not.toContain(KEY1.slice(0, 2));
    expect(masked).not.toContain(KEY1.slice(-2));
  });

  it("masks a short key completely", () => {
    expect(maskSecret("aabb")).toBe("•••• (2 B)");
    expect(maskSecret("")).toBe("");
  });

  it("accepts even-length hex with whitespace and 0x", () => {
    expect(isHexSecret("0xAA bb")).toBe(true);
    expect(isHexSecret("abc")).toBe(false);
    expect(isHexSecret("zz")).toBe(false);
    expect(isHexSecret("")).toBe(false);
  });

  it("recognises key-carrying columns", () => {
    expect(["KeyHex", "key_hex", "MasterKey", "secret", "Key"].every(isSecretColumn)).toBe(true);
    expect(["KeyOffset", "KeyLength", "Proven"].some(isSecretColumn)).toBe(false);
    expect(cellText("KeyHex", KEY2)).toBe(maskSecret(KEY2));
    expect(cellText("KeyOffset", 5)).toBe("5");
    expect(cellText("Detail", null)).toBe("—");
  });
});

describe("validateDraft / buildSynthRequest", () => {
  it("defaults a plugin name from the oracle kind", () => {
    expect(defaultPluginName("gocryptfs-gcm")).toBe("memdiver_gocryptfs");
  });

  it("sends one dump's key as a string", () => {
    expect(validateDraft(draft())).toEqual([]);
    const req = buildSynthRequest(draft());
    expect(req.secret_hex).toBe(KEY1);
    expect(req.oracle_sample_path).toBe("/data/run_0001/cipher");
    expect(req.case_dir).toBe("my-case");
    expect(req.context).toBe(64);
    expect(req.verify_on).toEqual(["msl"]);
    expect(req.full_image).toBeUndefined();
  });

  it("sends one key per dump and a per-dump sample list", () => {
    const d = draft({ dumps: [
      { path: RUN1, secretHex: KEY1, samplePath: "" },
      { path: RUN2, secretHex: ` 0x${KEY2} `, samplePath: CIPHER2 },
    ] });
    expect(validateDraft(d)).toEqual([]);
    const req = buildSynthRequest(d);
    expect(req.dump_paths).toEqual([RUN1, RUN2]);
    expect(req.secret_hex).toEqual([KEY1, KEY2]);
    expect(req.oracle_sample_path).toEqual([null, CIPHER2]);
  });

  it("broadcasts the first dump's key when the others are blank", () => {
    const d = draft({ dumps: [
      { path: RUN1, secretHex: KEY1, samplePath: "" }, { path: RUN2, secretHex: "", samplePath: "" },
    ] });
    expect(buildSynthRequest(d).secret_hex).toBe(KEY1);
    expect(buildSynthRequest(d).oracle_sample_path).toBeUndefined();
  });

  it("refuses a key given only for a later dump, bad hex, a bad name and no dumps", () => {
    expect(validateDraft(draft({ dumps: [
      { path: RUN1, secretHex: "", samplePath: "" }, { path: RUN2, secretHex: KEY2, samplePath: "" },
    ] }))).toEqual(["synth.error.secretPerDump"]);
    expect(validateDraft(draft({ dumps: [{ path: RUN1, secretHex: "abc", samplePath: "" }] })))
      .toEqual(["synth.error.secretHex"]);
    expect(validateDraft(draft({ name: "1bad-name" }))).toEqual(["synth.error.name"]);
    expect(validateDraft(draft({ dumps: [{ path: " ", secretHex: "", samplePath: "" }] })))
      .toContain("synth.error.noDumps");
    expect(validateDraft(draft({ pid: "x", context: "-1" })))
      .toEqual(["synth.error.context", "synth.error.pid"]);
  });

  it("adds the full image block only with an image", () => {
    const req = buildSynthRequest(draft({
      fullImage: "/img.lime", pid: "9878", fullImageSample: "/vault", fullImageSecretHex: KEY2,
      symbolDirs: "/isf\n\n/isf2 ", verifyOnMsl: false, allowHighEntropy: true,
    }), { key_hex: "c0ffee" });
    expect(req).toMatchObject({
      full_image: "/img.lime", pid: 9878, full_image_sample: "/vault", full_image_secret_hex: KEY2,
      symbol_dirs: ["/isf", "/isf2"], verify_on: [], allow_high_entropy_context: true, key_hex: "c0ffee",
    });
    expect(buildSynthRequest(draft({ pid: "9878" })).pid).toBeUndefined();
  });
});

describe("vol_command -> exec request", () => {
  it("splits shell words with single and double quotes", () => {
    expect(shellSplit(`vol -p 'a b;c' -f "d \\"e\\"" x\\ y`)).toEqual(["vol", "-p", "a b;c", "-f", 'd "e"', "x y"]);
    expect(shellSplit(`a 'it'"'"'s'`)).toEqual(["a", "it's"]);
  });

  it("reruns the first dump's verdict without the installed dir and without args", () => {
    expect(execRequestFromVolCommand(SYNTH.verdicts[0].vol_command, REPO_PLUGINS)).toEqual({
      plugin: PLUGIN, image_path: RUN1, plugin_dirs: [CASE_PLUGINS], symbol_dirs: [], args: [],
    });
  });

  it("passes a later dump's own oracle sample", () => {
    expect(execRequestForVerdict(SYNTH, SYNTH.verdicts[1], REPO_PLUGINS)).toEqual({
      plugin: PLUGIN, image_path: RUN2, plugin_dirs: [CASE_PLUGINS], symbol_dirs: [],
      args: ["--oracle-sample", CIPHER2],
    });
  });

  it("keeps every -p dir when the installed dir is unknown, and reads -s and --pid", () => {
    const cmd = `vol -s /isf --offline -p '${REPO_PLUGINS};${CASE_PLUGINS}' -f /img.lime ${PLUGIN} --pid 9878`;
    expect(execRequestFromVolCommand(cmd, null)).toEqual({
      plugin: PLUGIN, image_path: "/img.lime", plugin_dirs: [REPO_PLUGINS, CASE_PLUGINS],
      symbol_dirs: ["/isf"], args: ["--pid", "9878"],
    });
  });

  it("prefers the verdict's own exec request, minus the installed dir", () => {
    const verdict = {
      ...SYNTH.verdicts[0], vol_command: "vol -f /parsed.msl parsed.Plugin",
      exec: { plugin: PLUGIN, image_path: "/img.lime", plugin_dirs: [`${REPO_PLUGINS}/`, CASE_PLUGINS],
        symbol_dirs: ["/isf"], args: ["--pid", "9878"] },
    };
    expect(execRequestForVerdict(SYNTH, verdict, REPO_PLUGINS)).toEqual({
      plugin: PLUGIN, image_path: "/img.lime", plugin_dirs: [CASE_PLUGINS], symbol_dirs: ["/isf"],
      args: ["--pid", "9878"],
    });
    expect(execRequestForVerdict(SYNTH, verdict, null).plugin_dirs).toEqual([`${REPO_PLUGINS}/`, CASE_PLUGINS]);
  });

  it("fills the optional lists of a sparse exec request", () => {
    const verdict = { ...SYNTH.verdicts[0], exec: { plugin: PLUGIN, image_path: RUN1 } };
    expect(execRequestForVerdict(SYNTH, verdict, REPO_PLUGINS)).toEqual({
      plugin: PLUGIN, image_path: RUN1, plugin_dirs: [], symbol_dirs: [], args: [],
    });
  });

  it("drops only the installed dir, trailing slashes ignored", () => {
    expect(withoutMemdiverDir(["/a/", "/b"], "/a")).toEqual(["/b"]);
    expect(withoutMemdiverDir(["/a", "/b"], "/a//")).toEqual(["/b"]);
    expect(withoutMemdiverDir(["/a", "/b"], null)).toEqual(["/a", "/b"]);
  });

  it("falls back to the recipe's plugin over the verdict's dump", () => {
    expect(execRequestForVerdict(SYNTH, { ...SYNTH.verdicts[0], vol_command: "" }, REPO_PLUGINS)).toEqual({
      plugin: PLUGIN, image_path: RUN1, plugin_dirs: [CASE_PLUGINS], args: [],
    });
  });

  it("lists row columns without __children and recognises proven cells", () => {
    expect(execColumns(EXEC.rows)).toEqual(["Detail", "KeyHex", "KeyOffset", "Proven", "Scope"]);
    expect(isProvenCell("oracle:gocryptfs-gcm")).toBe(true);
    expect(isProvenCell("")).toBe(false);
    expect(isProvenCell(null)).toBe(false);
  });
});
