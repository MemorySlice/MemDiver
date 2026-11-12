# Relation to Upstream Volatility 3

## 5-level paging (LA57)

Stock Volatility 3 (2.27.0 and the contest target 2.28.2) cannot translate addresses on a Linux image that runs with five-level page tables: `linux.pslist` finds no process. Two upstream pull requests address this:

- [#1939](https://github.com/volatilityfoundation/volatility3/pull/1939) (amebius)
- [#1991](https://github.com/volatilityfoundation/volatility3/pull/1991) (ricardojrdez, with tests)

Our x86_64 reference images include one captured with five-level paging active (`cpuinfo_la57` true, mappings above 2^47). On it:

| Build | `linux.pslist` on the 5-level reference image |
|---|---|
| stock 2.27.0 | 0 rows |
| PR #1991 (head 2b531c77) | 155 rows, 7.2 s |
| stock 2.27.0 with this suite's stacker | 155 rows, 6.8 s; PID and name columns identical to PR #1991 |

Across the 20-image x86_64 LiME corpus, PR #1991 fixes `pslist` on all 10 five-level images (0 rows before, 75 to 130 after, 95 to 99 % of the processes in the guests' own `ps` snapshots), leaves the 10 four-level images identical, and crashes on none. A control build of the pull request's merge base also gives 0 on five-level images, so the effect is the pull request's. `proc.Maps --pid 1` goes from 0 to 184 rows on one image. With this suite's stacker 9 of the 10 five-level images match the pull request's counts; the tenth has no `kallsyms`, and Volatility 2.27 builds no kernel layer for it at all.

## What the suite's stacker does

`LinuxLA57IntelStacker` is a fallback so that the entry works on a judge's stock install. It is self-contained and **steps aside when Volatility supports five-level paging itself**: it checks for `intel.LinuxIntel32e_LA57` and does nothing when that class exists. It acts only on the exact stock four-level layer classes, so it cannot change the result on a four-level image. Details are in [Technical details](TECHNICAL_DETAILS.md#stackers-5-level-paging-la57).

We did not write a third pull request. Two pull requests are open.

## Validation data for the pull requests

The corpus check script is [`scripts/la57_corpus_check.py`](https://github.com/MemorySlice/MemDiver/blob/main/scripts/la57_corpus_check.py). The table above (and the per-image results) is intended as a comment on pull request #1991, to be posted by the project maintainer under their own account. The comment is not reproduced here.

## Other upstream facts the suite relies on

- Stock Volatility 3 has no AArch64 Linux layer (checked on 2.27.0, the development branch at 2.28.3, and PR #1991). Only a third-party fork has one. See [Compatibility](COMPATIBILITY.md).
- Volatility's `-p` option takes several directories separated by `;` on every operating system.
- Without a `--cache-path` per run, concurrent Volatility processes can race on the shared symbol cache.
