---
myst:
  html_meta:
    "description lang=en": "Hand-build a Volatility 3 ISF kernel profile from a raw image: probes, provenance-tracked drafts, a ground-truth try-loop, export."
---

# The ISF workbench

An ISF is the kernel profile Volatility 3 needs to read structures such as
`task_struct`. Normally [the profile chain](vol3.md#the-profile-chain)
(cache, pakunoda) produces one. The workbench is for the kernels where it
cannot: edge devices and exotic builds. You find the kernel's facts in the
raw image, assemble a draft with per-entry provenance, prove it by running a
plugin against ground truth, and export a `.isf.json`.

Install the extras: `pip install "memdiver[image]"` and `memdiver[disasm]`
(capstone, needed only for disassembly and code evidence).

:::{warning}
**Wrong offsets are silent.** Volatility 3 loads a profile with wrong offsets
and returns plausible wrong rows. Never trust a draft you have not tried
against ground truth. The try-loop below exists for exactly this.
:::

## When to use it

- `memdiver image profile` found no profile and you still need `pslist`.
- You want to check an existing ISF claim by claim (`isf draft import` then
  `isf draft diff`).
- You want a kernel view with no profile at all (see
  [below](#a-kernel-view-without-an-isf)).

## Probes

A probe reads one kind of fact from the raw image. The CLI form is
`memdiver isf probe IMAGE PROBE`; the web form is **Probe the image** in the
**ISF Builder** panel (**ProbeRunner**).

| Probe | Finds |
|---|---|
| `viability` | whether the image can be walked at all |
| `banner`, `utsname` | the kernel version string |
| `vmcoreinfo` | the kernel's own symbol and struct-offset note |
| `kallsyms` | the symbol table (name to address) |
| `btf` | type information, when the kernel carries it |
| `init_task` | the address of the first task |
| `page_table_root` | the physical address of the kernel page tables |
| `ksymtab` | exported symbols |
| `layout_legs` | struct field offsets inferred from the live process list |

`--arch` sets the architecture (default `auto`). `--params` takes JSON such as
`'{"limit": 50, "va_bits": 48}'`; pass `va_bits` 57 only when the probes say
the image uses 5-level paging. Rows carry `Location`s. Check `counts`,
`truncated` and `timings` before relying on a result.

Add `--case CASE --draft NAME` and the probe feeds its findings straight into
the draft, each with provenance (`kallsyms`, `btf`, `vmcoreinfo` and
`layout_legs` are the feedable ones). `layout_legs` yields many claims and also
refusals. Read the refusals.

**`init_task` is only used when verified.** MemDiver takes it from pakunoda's
`find_init_task`, which reports `source`, `verified` and `checks`. An
unverified base is refused (`isf.init_task_unverified`) and the message names
the source, the checks and the top candidates. It is never guessed. A
banner-delta derivation is kept only as an unverified fallback, labelled as
such. This matters: on one fedora-40 image a `swapper`-named task was a
never-booted stale kernel copy, and the old derivation walked it silently. A
booted `init_task` has a live `tasks` list, and a matching name alone proves
nothing.

## Drafts

A draft is an **append-only operation log** with a materialized view.

```bash
memdiver isf draft create CASE IMAGE mydraft x86_64 --banner "Linux version …"
memdiver isf draft set CASE IMAGE mydraft struct --args '{"name":"list_head","size":16}' \
  --tier upstream_constant --source "include/linux/types.h" --evidence "struct list_head"
memdiver isf draft get CASE IMAGE mydraft --origins --search task_struct
```

`CAPTURE` is the image sha256, and the image path is accepted in its place.

- **Operations:** `symbol`, `struct`, `field`, `base_type`, `enum`, `remove`
  (`--args` is JSON). Nothing is edited in place. `isf draft retract CASE
  CAPTURE DRAFT ENTRY` appends a retraction.
- **Provenance:** every claim carries `source`, `tier`, `evidence` (repeatable,
  one replayable line each) and `author`. The tiers are `exact`, `ordinal`,
  `population`, `code`, `crc_certified`, `upstream_constant`, `bound`
  (pakunoda's layout tiers) plus `imported`, `probe` and `manual`. Cite where
  each number came from.
- **state_id:** a hash of the draft's current state. A version id alone does
  not pin a state after a retraction, so tries and exports record the
  `state_id` too.
- **Versions:** `isf draft versions` lists history and `isf draft diff
  --against-version V` (or `--against-isf FILE`) compares.
- **Untyped fields:** an offset claimed without a type is kept in the draft but
  counted as `untyped_fields` and **never exported**. `isf draft get` shows the
  count.
- **Seeding:** `isf draft import CASE CAPTURE DRAFT ISF` seeds a draft from an
  existing ISF.

`isf draft validate --check-schema` lists the types Volatility 3 still
requires and the draft does not have. In the web UI, the **ISF Builder** panel
shows the draft tree (symbols, structs, base types, enums), edit forms for each
operation with a provenance block, a **Versions** list, and **Validation and
readiness**.

## The try-loop with a ground-truth diff

```bash
memdiver isf try IMAGE --case CASE --draft mydraft \
  --plugin linux.pslist --ground-truth vol3_pslist.txt -o try.json
```

`try` builds the profile from the draft, runs the plugin, and diffs the rows
against a known-good listing (Volatility 3 `pslist` text or `ps -ef` output).
It returns a verdict (`pass`, `partial`, `fail`, `unverified`, `error`) with
recall, precision (`--min-recall`, `--min-precision` set the thresholds),
missing and extra pids, mismatches and the **implicated** draft entries.
Rows without a ground truth are `unverified`, which is not a verdict. Every
try is filed as an `isf_try` annotation, so the history is kept (the web UI
lists it under **Past tries**).

A build failure lists every missing vol3-required type at once, read from the
installed Volatility 3 (it names only the first itself). Add field-less stub
structs for them, with tier `manual` and source `vol3_required`. Iterate: fix
the implicated entries, try again, until the verdict passes.

## Export

```bash
memdiver isf draft export CASE IMAGE mydraft --out mydraft.isf.json
```

- **Never export void members.** Placeholder (untyped) offsets are omitted
  from the output, because a `void` member made Volatility 3 crash at run time
  (`task_struct.is_valid` dereferences a member that exists but has no type).
- Export names are content-addressed: `<version>-<state_id>-<sha8>.isf.json`.
  An export is never overwritten, and a tampered file is restored.
- The draft's identity travels in `producer.memdiver_draft`, because Volatility
  3 rejects extra keys in the top-level metadata.
- `image open --draft NAME --case CASE` opens a kernel view on a draft
  directly (pin a state with `--draft-version`), so you can run plugins before
  exporting.

## A kernel view without an ISF

Some questions need only the page tables, not struct layouts: reading kernel
memory by virtual address, finding the banner, disassembling. `image open
--view kernel --no-profile` walks the page tables itself, on **x86_64** and
**aarch64** (Volatility 3 has no ARM layer, so this is the only kernel view
there).

```bash
memdiver image open IMAGE --view kernel --no-profile --case CASE
# or name the paging root yourself:
memdiver image open IMAGE --view kernel --no-profile --pgd 0x2a0c000 --arch x86_64 --va-bits 48
```

Without `--pgd`, the backend searches for a verified paging root, which can
take a while. Reference runs:

| Image | Result |
|---|---|
| arista-eos x86_64 | 90,792 leaves, 66,037 runs in 0.42 s; 2.51 GB captured, 438 KB failed; the banner read matches the ISF view |
| debian-12 arm64 | root `0x1d4fa0000` (from vmcoreinfo, verified); 450 runs in 5.8 s; 8.75 GB captured, 269 MB failed; `Linux version 6.1.0-44-cloud-arm64` found at `0xffff800008c100e8` |

Failed leaves (frame not in the image, unreadable table) are reported as
failed, never as zeros.

## Code evidence

The strongest support for a field offset is the kernel's own code. Which
struct member does a function touch?

```bash
memdiver isf code-evidence IMAGE __x64_sys_getuid --isf kernel.isf.json --base current
```

`FUNCTION` is a kallsyms name or a `0x` address. The command decodes the
function body and returns one `kernel_va` Location per access, with its
symbolic base (`current`, `arg0`, `static(sym)`, `deref(current+0x678)`). With
`--isf`, it joins `current`-based accesses to the ISF's `task_struct` members.
Cite each match as `--evidence` in `isf draft set`, and prefer offsets two
independent functions agree on.

It needs a **verified** `init_task` and page-table root. Otherwise reads are
refused (`code_evidence.image_reads_failed`). A declining architecture shows in
`coverage.declined`, never as an empty success. Only `current`-based accesses
join to `task_struct`; `arg0`-based ones are reported but not joined. The first
call takes about 35 s to set up a session.

Proven on real images:

- **x86_64, arista-eos** (against its shipped ISF): `__x64_sys_getuid` ->
  `current+0x678` = `task_struct.cred`, `deref+4` = `cred.uid`, `+0x88` =
  `cred.user_ns`; `__x64_sys_getppid` -> `current+0x478` = `real_parent`;
  `__task_pid_nr_ns` -> `current+0x4d0` = `thread_pid`, `deref+4` =
  `pid.level`. 6 of 6 `current`-based accesses matched.
- **aarch64:** `__arm64_sys_getuid` on ubuntu-24.04 -> `current+2120` =
  `task_struct.cred`; `__arm64_sys_getppid` on fedora-40 and sonic ->
  `current+2032` and `current+1368` = `real_parent`.

## Worked example: arista-eos

The reference run built a profile for an Arista EOS x86_64 image through the
CLI only. The shipped `.isf.json` was used for the final comparison, never as
input. The scripts and the claim log are in `docs/dev/semantic_workbench_p4_gate/`.

1. **Draft and symbols.** `isf draft create` for `x86_64`, then
   `isf probe … kallsyms --draft` fed 108,206 symbols in 1.7 s.
2. **Layout.** `isf probe … layout_legs --draft` added 104 claims in 5.5 s
   (offsets for `task_struct.tasks`, `pid`, `tgid`, `comm`, `real_parent`,
   `cred`, `mm`, `files` and more, with no types).
3. **Validate.** `isf draft validate` reported a missing `pointer` base type
   and `list_head` unusable.
4. **Round 1: 38 manual claims** (22 s): 13 x86_64 SysV LP64 base types,
   `list_head` (from `types.h`), the types for each layout-leg offset (from
   `sched.h` and `cred.h`), `kuid_t` and `kgid_t`, and the symbol types of
   `init_task`, `init_mm` and `init_files`. Tier `upstream_constant`, with the
   header named as evidence.
5. **Try.** Error at build. All 17 vol3-required types still missing were
   listed in a single try.
6. **Round 2:** 17 field-less stub structs (tier `manual`, source
   `vol3_required`), such as `file`, `dentry`, `inode`, `sock`, `page`.
7. **Try again.** `linux.pslist` **123/123 rows against `vol3_pslist.txt`, 0
   mismatches** on PID, TID, PPID, COMM and OFFSET. Against `ps_at_dump.txt` it
   matched 121 of 123, as expected, since `ps` itself and one ssh process were
   gone, and `sudo` and `avml` were extra.
8. **Compare with the shipped ISF.** Every fact the draft holds: **0
   disagreements**. 108,206 of 108,206 symbol addresses, 85 of 85 field
   offsets, 19 of 19 claimed field types, 13 of 13 base types and 3 of 3
   struct sizes were equal. 66 offsets stayed untyped (kept, not exported) and
   29 types were unsized stubs.

The draft ended at 161 operations. The same flow through MCP (`isf_try`)
passed 123/123 in 1.0 s.

### Four bugs only this real run found

All were fixed. They are the reason for the rules above.

1. Exported drafts never loaded, because Volatility 3's metadata schema forbids
   extra keys. The draft identity moved into `producer.memdiver_draft`.
2. Re-exporting the same state with different bytes blocked every later try.
   Export names became content-addressed.
3. Untyped `void` placeholders were exported and crashed `task_struct.is_valid`.
   They are now omitted.
4. `arch=auto` silently defaulted to x86_64. It now resolves from the draft,
   the banner, pakunoda or a page-table self-test, and otherwise fails with
   `isf.arch_undetected`.

## Driving it from MCP

Fetch the prompt `isf_workbench` (arguments `image_path`, `case`, `draft`), or
`code_evidence` for the code-evidence steps. The tools are `isf_probe`,
`isf_draft_create`, `isf_draft_set`, `isf_draft_get`, `isf_draft_validate`,
`isf_try`, `isf_draft_versions`, `isf_draft_diff`, `isf_draft_retract`,
`isf_draft_export`, `isf_draft_import`, `code_evidence` and `disasm`.
