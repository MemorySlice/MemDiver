"""CLI entry point for MemDiver — headless analysis and interactive UI."""

import argparse
import logging
import sys
from pathlib import Path

# The one app-layer import in this module: the parser's --max-returned default
# must be the SAME number the producer applies, or the CLI would advertise a
# cap the library does not use. numpy is already resolved by ``cli.consensus``
# above, so this costs no additional startup time.
from memdiver.app.tools_pipeline import DEFAULT_MAX_RETURNED_REGIONS
from memdiver.core.service_errors import CapabilityError

from ._shared import (
    _decrypt_parent_parser,
    _setup_logging,
    to_cli_exit,
)
from .dataset import (
    _cmd_analyze,
    _cmd_batch,
    _cmd_import,
    _cmd_mcp,
    _cmd_scan,
    _cmd_ui,
    _cmd_web,
)
from .consensus import (
    _cmd_consensus,
    _cmd_consensus_add,
    _cmd_consensus_begin,
    _cmd_consensus_finalize,
)
from .experiment import _cmd_experiment
from .pipeline import (
    _cmd_analyze_candidates,
    _cmd_auto_floor,
    _cmd_brute_force,
    _cmd_emit_plugin,
    _cmd_export,
    _cmd_export_keylog,
    _cmd_gen_kem_key,
    _cmd_import_dir,
    _cmd_inspect_pcap,
    _cmd_n_sweep,
    _cmd_search_reduce,
    _cmd_verify,
)

from .inspect import (
    _cmd_inspect,
)

logger = logging.getLogger("memdiver.cli")


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(prog="memdiver", description="MemDiver — Memory dump analysis platform")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("ui", help='Launch interactive Marimo UI (needs: pip install "memdiver[marimo]")').add_argument("extra_args", nargs="*", default=[])
    az = sub.add_parser("analyze", help="Analyze library directories")
    az.add_argument("library_dirs", nargs="+", help="Library directory paths")
    az.add_argument("--phase", required=True, help="Lifecycle phase")
    az.add_argument("--protocol-version", required=True, help="Protocol version")
    az.add_argument("--keylog-filename", default="keylog.csv")
    az.add_argument("--template", default="Auto-detect")
    az.add_argument("--max-runs", type=int, default=10)
    az.add_argument("--normalize", action="store_true")
    az.add_argument("--no-expand", action="store_true", help="Skip key expansion")
    az.add_argument("-o", "--output", help="Output JSON file")
    az.add_argument("-v", "--verbose", action="store_true")
    # scan
    sc = sub.add_parser("scan", help="Scan dataset root")
    sc.add_argument("--root", required=True, help="Dataset root path")
    sc.add_argument("--keylog-filename", default="keylog.csv")
    sc.add_argument("--protocols", nargs="*", help="Protocol names to scan")
    sc.add_argument("-o", "--output", help="Output JSON file")
    sc.add_argument("-v", "--verbose", action="store_true")
    # mcp
    mc = sub.add_parser("mcp", help="Start MCP server for AI integration (included in the base install)")
    mc.add_argument("--sse", action="store_true", help="Use SSE transport instead of stdio")
    mc.add_argument("--port", type=int, default=8080, help="SSE port (default: 8080)")
    mc.add_argument("-v", "--verbose", action="store_true")
    # batch
    bt = sub.add_parser("batch", help="Run batch analysis from config")
    bt.add_argument("--config", required=True, help="Batch config JSON file")
    bt.add_argument("-w", "--workers", type=int, default=1,
                    help="Number of parallel workers (default: 1)")
    bt.add_argument("-o", "--output", help="Output file")
    bt.add_argument("--output-format", choices=["json", "jsonl"], default=None,
                    help="Output format (overrides config); default: from config or 'json'")
    bt.add_argument("-v", "--verbose", action="store_true")
    # web (FastAPI + React — also the default when no command given)
    wp = sub.add_parser("web", help="Launch FastAPI + React web application (included in the base install)")
    wp.add_argument("--port", type=int, default=8080, help="Server port (default: 8080)")
    # consensus
    cs = sub.add_parser("consensus", help="Build consensus matrix from dumps",
                        parents=[_decrypt_parent_parser()])
    cs.add_argument("dumps", nargs="+", help="Dump file paths or directories")
    cs.add_argument("--normalize", action="store_true", help="ASLR-aware normalization")
    cs.add_argument("--min-length", type=int, default=16,
                    help="Minimum region length (default: 16)")
    cs.add_argument("--align", action="store_true",
                    help="Apply alignment filtering to KEY_CANDIDATE regions")
    cs.add_argument("--block-size", type=int, default=32,
                    help="Alignment block size (default: 32)")
    cs.add_argument("--alignment-bytes", type=int, default=16,
                    help="Memory alignment (default: 16)")
    cs.add_argument("--density", type=float, default=0.75,
                    help="Alignment density threshold (default: 0.75)")
    cs.add_argument("--convergence", action="store_true",
                    help="Run convergence sweep")
    cs.add_argument("--max-fp", type=int, default=0,
                    help="FP target for convergence (default: 0)")
    cs.add_argument("-o", "--output", help="Output JSON file")
    cs.add_argument("-v", "--verbose", action="store_true")
    # incremental consensus (Welford-backed, persisted state)
    cb = sub.add_parser(
        "consensus-begin",
        help="Create a new incremental consensus session on disk",
    )
    cb.add_argument("--state", required=True, help="Path to session state JSON")
    cb.add_argument("--size", type=int, required=True,
                    help="Consensus width in bytes")
    cb.add_argument("-v", "--verbose", action="store_true")
    ca = sub.add_parser(
        "consensus-add",
        help="Fold one dump into an existing incremental consensus session",
        parents=[_decrypt_parent_parser()],
    )
    ca.add_argument("--state", required=True, help="Path to session state JSON")
    ca.add_argument("dump", help="Path to a .dump or .msl file")
    ca.add_argument("-v", "--verbose", action="store_true")
    cf = sub.add_parser(
        "consensus-finalize",
        help="Materialize variance + classifications from a session",
    )
    cf.add_argument("--state", required=True, help="Path to session state JSON")
    cf.add_argument("-o", "--output", help="Output JSON file")
    cf.add_argument("-v", "--verbose", action="store_true")
    # search-reduce
    sr = sub.add_parser(
        "search-reduce",
        help="Reduce candidate set: variance → alignment → entropy",
        parents=[_decrypt_parent_parser()],
    )
    sr.add_argument("--state", required=True, help="Path to consensus state JSON")
    sr.add_argument("--reference-dump", required=True,
                    help="One dump file used for per-region entropy sampling")
    sr.add_argument("--alignment", type=int, default=8)
    sr.add_argument("--block-size", type=int, default=32)
    sr.add_argument("--density-threshold", type=float, default=0.5)
    sr.add_argument("--min-variance", type=float, default=3000.0,
                    help="Variance floor for candidate regions (default 3000). "
                         "The output's 'recommended_floor' is a data-driven "
                         "suggestion to consider here (0.0 = too few dumps / no "
                         "crypto component: keep everything).")
    sr.add_argument("--entropy-window", type=int, default=32)
    sr.add_argument("--entropy-threshold", type=float, default=4.5)
    sr.add_argument("--min-region", type=int, default=16)
    sr.add_argument("--max-region", type=int, default=0,
                    help="Drop regions LONGER than this many bytes (0 = unbounded)")
    sr.add_argument("--classes",
                    help="Comma-separated ByteClass bands to keep: invariant, "
                         "structural, pointer, key_candidate. Applied IN "
                         "ADDITION to --min-variance, whose 3000 default "
                         "already excludes everything below key_candidate — "
                         "pass --min-variance 0 with a multi-class query.")
    sr.add_argument("--order", choices=("offset", "rank"), default="offset",
                    help="Order of the emitted regions (default offset). Every "
                         "region carries 'rank' and 'score' either way.")
    sr.add_argument("-o", "--output", required=True, help="Output candidates.json")
    sr.add_argument("-v", "--verbose", action="store_true")
    # analyze-candidates (the exploratory path: no oracle, no capture)
    ac = sub.add_parser(
        "analyze-candidates",
        help="Rank candidate regions across N dumps (no oracle needed)",
        parents=[_decrypt_parent_parser()],
    )
    ac.add_argument("dumps", nargs="+", help="Dump file paths or directories (N >= 2)")
    ac.add_argument("--classes",
                    help="Comma-separated ByteClass bands to keep: invariant, "
                         "structural, pointer, key_candidate. Real key material "
                         "is class-MIXED, so prefer all three non-invariant "
                         "bands over key_candidate alone.")
    ac.add_argument("--min-variance", type=float, default=None,
                    help="Variance floor. Left unset it resolves against "
                         "--classes: 3000 with no class named, 0 with one, so a "
                         "class query is not silently re-narrowed by this floor.")
    ac.add_argument("--min-region", type=int, default=16)
    ac.add_argument("--max-region", type=int, default=0,
                    help="Drop regions LONGER than this many bytes (0 = unbounded)")
    ac.add_argument("--alignment", type=int, default=8)
    ac.add_argument("--block-size", type=int, default=32)
    ac.add_argument("--density-threshold", type=float, default=0.5)
    ac.add_argument("--entropy-window", type=int, default=32)
    ac.add_argument("--entropy-threshold", type=float, default=4.5)
    ac.add_argument("--order", choices=("offset", "rank"), default="rank",
                    help="Order of the emitted regions (default rank, best "
                         "first). Every region carries 'rank' and 'score' "
                         "either way.")
    ac.add_argument("--max-returned", type=int,
                    default=DEFAULT_MAX_RETURNED_REGIONS,
                    help=f"Cap the returned regions to this many best-ranked "
                         f"rows (default {DEFAULT_MAX_RETURNED_REGIONS}, "
                         f"0 = uncapped)")
    ac.add_argument("--normalize", action="store_true",
                    help="ASLR-aware normalization for native .msl inputs")
    ac.add_argument("--project-id", default="",
                    help="Project to file the stored comparison under")
    ac.add_argument("-o", "--output", help="Output JSON file")
    ac.add_argument("-v", "--verbose", action="store_true")
    # brute-force
    bf = sub.add_parser(
        "brute-force",
        help="Iterate candidates through a user oracle script",
        parents=[_decrypt_parent_parser()],
    )
    bf.add_argument("--candidates", required=True, help="candidates.json from search-reduce")
    bf.add_argument("--dump", required=True, help="Reference dump file")
    bf.add_argument("--oracle", help="Path to user Python oracle script "
                    "(mutually exclusive with --pcap)")
    bf.add_argument("--oracle-config", help="Optional TOML config passed to build_oracle")
    bf.add_argument("--pcap", help="pcap/pcapng of the same TLS session; confirm a "
                    "recovered key decrypts real captured records via the "
                    "first-party trusted oracle (mutually exclusive with --oracle)")
    bf.add_argument("--tls-client-random", help="Hex TLS client_random restricting "
                    "the pcap oracle to one session")
    bf.add_argument("--pcap-max-records", type=int, default=None,
                    help="Cap the encrypted application-data records each direction "
                    "of a captured session contributes to the pcap oracle "
                    "(default: 16). Lower it for speed, raise it for coverage; "
                    "'inspect-pcap' reports whether a capture is being clipped")
    bf.add_argument("--pcap-max-challenges", type=int, default=None,
                    help="Cap the total challenges the pcap oracle keeps across "
                    "all sessions (default: uncapped). A cap silently discards "
                    "verification work, so it is set explicitly, never by default")
    bf.add_argument("--persist-ground-truth", action="store_true",
                    help="Record confirmed hits in the project ground-truth ledger "
                    "(opt-in; no-op if the DuckDB backend is unavailable)")
    bf.add_argument("--key-sizes", default="32", help="Comma-separated key sizes in bytes")
    bf.add_argument("--stride", type=int, default=1,
                    help="Candidate offset step in bytes. Only offsets that are multiples of the stride are tested, so a secret that is not stride-aligned is never reached; the default 1 walks every offset (full coverage). Raise it to trade coverage for speed (default: 1)")
    bf.add_argument("--jobs", type=int, default=0,
                    help="Brute-force worker processes. 0 (default) auto-selects: serial for a small or --first-hit sweep, otherwise a small pool. Any explicit value is used verbatim; 1 forces serial (default: 0)")
    bf.add_argument("--first-hit", action="store_true",
                    help="Stop at the first verified candidate (default: exhaustive)")
    bf.add_argument("--state", help="Consensus state path (attaches neighborhood variance)")
    bf.add_argument("--top-k", type=int, default=10)
    bf.add_argument("-o", "--output", required=True, help="Output hits.json")
    bf.add_argument("-v", "--verbose", action="store_true")
    # n-sweep
    ns = sub.add_parser(
        "n-sweep",
        help="Sweep N=1..N_max; emit survivor-count curve + oracle hits",
        parents=[_decrypt_parent_parser()],
    )
    ns.add_argument("--runs-dir", required=True, help="Directory containing run_* subdirs")
    ns.add_argument("--dump-glob", default="*.msl", help="Glob under each run")
    ns.add_argument("--n-values", default="1,3,5,10,20,30,50,75,100")
    ns.add_argument("--alignment", type=int, default=8)
    ns.add_argument("--block-size", type=int, default=32)
    ns.add_argument("--density-threshold", type=float, default=0.5)
    ns.add_argument("--min-variance", type=float, default=3000.0)
    ns.add_argument("--entropy-window", type=int, default=32)
    ns.add_argument("--entropy-threshold", type=float, default=4.5)
    ns.add_argument("--min-region", type=int, default=16)
    ns.add_argument("--oracle", required=True, help="Path to user oracle script")
    ns.add_argument("--oracle-config", help="Optional TOML config")
    ns.add_argument("--key-sizes", default="32")
    ns.add_argument("--stride", type=int, default=1,
                    help="Candidate offset step in bytes. Only offsets that are multiples of the stride are tested, so a secret that is not stride-aligned is never reached; the default 1 walks every offset (full coverage). Raise it to trade coverage for speed (default: 1)")
    ns.add_argument("--first-hit", action="store_true")
    ns.add_argument("--escalate", action="store_true",
                    help="If no checkpoint finds a hit, run a floor-free "
                         "descending-variance sweep once at the terminal N "
                         "(reuses the in-memory variance; no re-fold)")
    ns.add_argument("--escalate-oracle-budget", type=int, default=None,
                    help="Optional cap on oracle calls during escalation "
                         "(default: exhaustive)")
    ns.add_argument("--output-dir", required=True, help="Directory for report.{json,md,html}")
    ns.add_argument("-v", "--verbose", action="store_true")
    # auto-floor
    af = sub.add_parser(
        "auto-floor",
        help="Automated ground-truth-free variance-floor selection (single verdict)",
        parents=[_decrypt_parent_parser()],
    )
    af.add_argument("--state", required=True, help="Path to consensus state JSON")
    af.add_argument("--reference-dump", required=True,
                    help="One dump the oracle verifies candidates against")
    af.add_argument("--oracle", required=True, help="Path to user Python oracle script")
    af.add_argument("--oracle-config", help="Optional TOML config passed to build_oracle")
    af.add_argument("--key-sizes", default="32", help="Comma-separated key sizes in bytes")
    af.add_argument("--stride", type=int, default=1,
                    help="Candidate offset step in bytes. The default 1 walks every offset (full coverage); raise it to trade coverage for speed (default: 1)")
    af.add_argument("--alignment", type=int, default=8)
    af.add_argument("--block-size", type=int, default=32)
    af.add_argument("--density-threshold", type=float, default=0.5)
    af.add_argument("--entropy-window", type=int, default=32)
    af.add_argument("--entropy-threshold", type=float, default=4.5)
    af.add_argument("--min-region", type=int, default=16)
    af.add_argument("--phi0-method", default="pmin", choices=["pmin", "otsu"],
                    help="Recommended-floor method: 'pmin' (phi=p_min*sigma_k^2, "
                         "default) or 'otsu' (legacy data-driven valley fit)")
    af.add_argument("--p-min", type=float, default=0.35,
                    help="Retention policy for --phi0-method pmin: retain keys "
                         "whose per-run correspondence >= p_min (default 0.35)")
    af.add_argument("--coverage", type=float, default=None,
                    help="Precomputed cross-run coverage-intersection C∩ in [0,1] "
                         "(gates/qualifies the ABSENT verdict)")
    af.add_argument("--correspondence", type=float, default=None,
                    help="Precomputed correspondence score in [0,1] (reported)")
    af.add_argument("--filter-recall", type=float, default=None,
                    help="Precomputed entropy/alignment filter recall in [0,1]")
    af.add_argument("--min-coverage", type=float, default=0.80)
    af.add_argument("--self-test-trials", type=int, default=8,
                    help="Oracle self-test random-negative probes (lower for "
                         "one-shot/rate-limited oracles; each costs one call)")
    af.add_argument("--oracle-budget", type=int, default=None,
                    help="Max total oracle calls; if the maximal set is not "
                         "exhausted within budget, the verdict is INCONCLUSIVE(cost), "
                         "never a false ABSENT")
    af.add_argument("--alignment-quality", type=float, default=None,
                    help="Precomputed per-region alignment quality in [0,1]; below "
                         "--min-alignment a no-hit is INCONCLUSIVE(alignment)")
    af.add_argument("--min-alignment", type=float, default=0.5)
    af.add_argument("--managed-region", action="store_true",
                    help="Target is a managed runtime / moving-GC heap: a no-hit is "
                         "INCONCLUSIVE(regime) (off-grid object headers may hide the key)")
    af.add_argument("--positive-control",
                    help="Hex of a known-good key for the oracle self-test (optional)")
    af.add_argument("--output-dir", required=True, help="Directory for verdict.json/report.md")
    af.add_argument("-v", "--verbose", action="store_true")
    # emit-plugin
    ep_emit = sub.add_parser(
        "emit-plugin",
        help="Emit a Volatility3 plugin from a brute-force hit neighborhood",
        parents=[_decrypt_parent_parser()],
    )
    ep_emit.add_argument("--hit", required=True, help="hits.json from brute-force")
    ep_emit.add_argument("--reference", required=True, help="Reference dump file")
    ep_emit.add_argument("--name", required=True, help="Plugin class / rule name")
    ep_emit.add_argument("--hit-index", type=int, default=0)
    ep_emit.add_argument("--description")
    ep_emit.add_argument(
        "--variance-threshold", type=float, default=None,
        help="Max variance for static bytes (default: 2000). Lower values "
        "produce more wildcards → more cross-session robust patterns.",
    )
    ep_emit.add_argument("-o", "--output", required=True, help="Output .py file path")
    ep_emit.add_argument("-v", "--verbose", action="store_true")
    # export
    ex = sub.add_parser("export", help="Export pattern as YARA/JSON/Volatility3",
                        parents=[_decrypt_parent_parser()])
    ex.add_argument("dumps", nargs="+", help="Dump file paths or directories")
    ex.add_argument("--offset", type=lambda x: int(x, 0), default=None,
                    help="Region offset (hex or decimal)")
    ex.add_argument("--length", type=int, default=None, help="Region length in bytes")
    ex.add_argument("--auto", action="store_true",
                    help="Auto-detect largest KEY_CANDIDATE region")
    ex.add_argument("--context", type=int, default=32,
                    help="Bytes of context around auto-detected region (default: 32)")
    ex.add_argument("--name", default="memdiver_pattern", help="Pattern name")
    ex.add_argument("--format", default="volatility3",
                    choices=["yara", "json", "volatility3", "vol3"])
    ex.add_argument("--min-static-ratio", type=float, default=0.3,
                    help="Minimum static byte ratio (default: 0.3)")
    ex.add_argument("--align", action="store_true",
                    help="Use alignment-filtered candidates for auto-detection")
    ex.add_argument("-o", "--output", help="Output file path")
    ex.add_argument("-v", "--verbose", action="store_true")
    # export-keylog
    ekl = sub.add_parser(
        "export-keylog",
        help="Emit a Wireshark-loadable NSS key log from recovered TLS secrets",
    )
    ekl.add_argument(
        "--secrets", required=True,
        help="JSON file: list of {secret_type, client_random, secret} dicts "
             "(client_random/secret are hex strings)",
    )
    ekl.add_argument("-o", "--output",
                     help="Output key-log file path (default: stdout)")
    ekl.add_argument("-v", "--verbose", action="store_true")
    # inspect-pcap
    ipc = sub.add_parser(
        "inspect-pcap",
        help="Summarise the TLS sessions in a capture (the pcap arm/validate step)",
    )
    ipc.add_argument("pcap", help="Path to a .pcap/.pcapng capture")
    ipc.add_argument("--pcap-max-records", type=int, default=None,
                     help="Cap the encrypted application-data records each "
                          "direction contributes (default: 16). Pass the same "
                          "value the brute-force run will use so the reported "
                          "caps are the caps actually in force")
    ipc.add_argument("--pcap-max-challenges", type=int, default=None,
                     help="Cap the total decryption challenges kept ACROSS all "
                          "sessions (default: uncapped). TLS 1.3 yields several "
                          "challenges per record, so this is not a record count")
    ipc.add_argument("-o", "--output",
                     help="Output JSON file (default: stdout)")
    ipc.add_argument("-v", "--verbose", action="store_true")
    # gen-kem-key
    gk = sub.add_parser(
        "gen-kem-key",
        help="Generate a KEM keypair for encrypted-MSL recipients (spec §10.4)",
    )
    gk.add_argument("--mechanism", required=True,
                    choices=["X25519", "ML-KEM-768", "ML-KEM-1024",
                             "X25519+ML-KEM-768"],
                    help="Key encapsulation mechanism")
    gk.add_argument("--public-out", required=True,
                    help="Output path for the recipient public key")
    gk.add_argument("--private-out", required=True,
                    help="Output path for the recipient private key "
                         "(use later via --kem-key-file)")
    gk.add_argument("-v", "--verbose", action="store_true")
    # import
    im = sub.add_parser(
        "import", help="Import a dump (raw .dump, ELF core, or minidump) to .msl")
    im.add_argument("dump_file", help="Dump file path (.dump/.core/.dmp)")
    im.add_argument("-o", "--output", help="Output .msl file path")
    im.add_argument("--pid", type=int, default=0, help="Process ID")
    im.add_argument("--keylog", help="Keylog file for key hints")
    im.add_argument("-v", "--verbose", action="store_true")
    # import-dir
    imd = sub.add_parser(
        "import-dir",
        help="Import all dumps (.dump/.dmp/.core) in a directory to .msl")
    imd.add_argument("run_dir", help="Run directory path")
    imd.add_argument("-o", "--output-dir", required=True, help="Output directory")
    imd.add_argument("--keylog-filename", default="keylog.csv")
    imd.add_argument("-v", "--verbose", action="store_true")
    # verify
    vr = sub.add_parser("verify", help="Verify candidate key via decryption",
                        parents=[_decrypt_parent_parser()])
    vr.add_argument("dump", help="Dump file path")
    vr.add_argument("--offset", type=lambda x: int(x, 0), required=True,
                    help="Candidate key offset (hex or decimal)")
    vr.add_argument("--length", type=int, default=32, help="Key length (default: 32)")
    vr.add_argument("--ciphertext-hex", required=True, help="Known ciphertext (hex)")
    vr.add_argument("--iv-hex", help="IV (hex, default: 0x00010203...0f)")
    vr.add_argument("--nonce-hex", help="AEAD nonce (hex, for GCM/ChaCha20-Poly1305)")
    vr.add_argument("--aad-hex", help="AEAD associated data (hex, optional)")
    vr.add_argument("--tag-hex", help="AEAD authentication tag (hex, for GCM/ChaCha20-Poly1305)")
    vr.add_argument("--cipher", default="AES-256-CBC", help="Cipher name")
    vr.add_argument("-o", "--output", help="Output JSON file")
    vr.add_argument("-v", "--verbose", action="store_true")
    # experiment
    ep_exp = sub.add_parser("experiment",
                            help="Run full dump-and-analyze experiment",
                            parents=[_decrypt_parent_parser()])
    ep_exp.add_argument("--target", required=True,
                        help="Target script path (e.g., aes_sample_process.py)")
    ep_exp.add_argument("--num-runs", type=int, default=30,
                        help="Number of dump iterations per tool (default: 30)")
    ep_exp.add_argument("--tools", help="Comma-separated dump tools (default: auto-detect)")
    ep_exp.add_argument("--output-dir", type=Path, default=Path("./experiment_output"),
                        help="Output directory (default: ./experiment_output)")
    ep_exp.add_argument("--convergence", action="store_true",
                        help="Run convergence sweep after dumping")
    ep_exp.add_argument("--max-fp", type=int, default=0,
                        help="FP target for convergence (default: 0)")
    ep_exp.add_argument("--export-format", default="volatility3",
                        choices=["yara", "json", "volatility3"],
                        help="Auto-export format (default: volatility3)")
    ep_exp.add_argument("-o", "--output", help="Output JSON results file")
    ep_exp.add_argument("-v", "--verbose", action="store_true")
    # inspect — low-level dump / structured-MSL inspection views. Nested
    # `inspect <action>` group reusing the pure tools_inspect / tools_xref
    # functions behind the HTTP `/api/inspect` endpoints and the MCP server.
    dp = _decrypt_parent_parser()
    insp = sub.add_parser(
        "inspect",
        help="Low-level dump / structured-MSL inspection views (hex, entropy, "
             "strings, byte-search, page-states, session-info, vas, processes, "
             "modules, handles, xref, structure)",
    )
    insp_sub = insp.add_subparsers(dest="inspect_action")
    # inspect hex
    ih = insp_sub.add_parser("hex", parents=[dp],
                             help="Hex + ASCII dump of a byte range")
    ih.add_argument("dump_path", help="Dump (.dump/.core) or .msl file path")
    ih.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                    help="Start offset (hex or decimal, default: 0)")
    ih.add_argument("--length", type=int, default=256,
                    help="Bytes to read (default: 256)")
    ih.add_argument("--view", choices=["raw", "vas"], default="raw",
                    help="MSL byte source: raw container or flattened VAS")
    ih.add_argument("-o", "--output", help="Output JSON file")
    ih.add_argument("-v", "--verbose", action="store_true")
    # inspect entropy
    ie = insp_sub.add_parser("entropy", parents=[dp],
                             help="Shannon entropy profile of a region")
    ie.add_argument("dump_path", help="Dump or .msl file path")
    ie.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                    help="Start offset (hex or decimal, default: 0)")
    ie.add_argument("--length", type=int, default=0,
                    help="Region length (0 = whole file)")
    ie.add_argument("--window", type=int, default=32,
                    help="Sliding window size (default: 32)")
    ie.add_argument("--step", type=int, default=16,
                    help="Window step (default: 16)")
    ie.add_argument("--threshold", type=float, default=7.5,
                    help="High-entropy region threshold (default: 7.5)")
    ie.add_argument("-o", "--output", help="Output JSON file")
    ie.add_argument("-v", "--verbose", action="store_true")
    # inspect strings
    istr = insp_sub.add_parser("strings", parents=[dp],
                               help="Extract printable strings")
    istr.add_argument("dump_path", help="Dump or .msl file path")
    istr.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                      help="Start offset (hex or decimal, default: 0)")
    istr.add_argument("--length", type=int, default=0,
                      help="Scan window length (0 = to end of file)")
    istr.add_argument("--min-length", type=int, default=4,
                      help="Minimum string length (default: 4)")
    istr.add_argument("--encoding", default="ascii",
                      help="String encoding (default: ascii)")
    istr.add_argument("--max-results", type=int, default=500,
                      help="Maximum strings to return (default: 500)")
    istr.add_argument("-o", "--output", help="Output JSON file")
    istr.add_argument("-v", "--verbose", action="store_true")
    # inspect byte-search
    ibs = insp_sub.add_parser("byte-search", parents=[dp],
                              help="Find all occurrences of a hex byte pattern")
    ibs.add_argument("dump_path", help="Dump or .msl file path")
    ibs.add_argument("--pattern", required=True,
                     help="Hex byte pattern (optional leading 0x)")
    ibs.add_argument("--view", choices=["raw", "vas"], default="raw",
                     help="MSL byte source: raw container or flattened VAS")
    ibs.add_argument("--max-results", type=int, default=500,
                     help="Maximum matches to return (default: 500)")
    ibs.add_argument("-o", "--output", help="Output JSON file")
    ibs.add_argument("-v", "--verbose", action="store_true")
    # inspect page-states
    ips = insp_sub.add_parser("page-states", parents=[dp],
                              help="MSL three-state page model (MSL only)")
    ips.add_argument("msl_path", help=".msl file path")
    ips.add_argument("-o", "--output", help="Output JSON file")
    ips.add_argument("-v", "--verbose", action="store_true")
    # inspect session-info
    isi = insp_sub.add_parser("session-info", parents=[dp],
                              help="MSL session metadata (MSL only)")
    isi.add_argument("msl_path", help=".msl file path")
    isi.add_argument("-o", "--output", help="Output JSON file")
    isi.add_argument("-v", "--verbose", action="store_true")
    # inspect vas
    iva = insp_sub.add_parser("vas", parents=[dp],
                              help="Per-dump VAS region layout (MSL only)")
    iva.add_argument("msl_path", help=".msl file path")
    iva.add_argument("-o", "--output", help="Output JSON file")
    iva.add_argument("-v", "--verbose", action="store_true")
    # inspect processes
    ipr = insp_sub.add_parser("processes", parents=[dp],
                              help="List PROCESS_TABLE entries (MSL only)")
    ipr.add_argument("msl_path", help=".msl file path")
    ipr.add_argument("-o", "--output", help="Output JSON file")
    ipr.add_argument("-v", "--verbose", action="store_true")
    # inspect modules
    imo = insp_sub.add_parser("modules", parents=[dp],
                              help="List loaded modules from MSL metadata (MSL only)")
    imo.add_argument("msl_path", help=".msl file path")
    imo.add_argument("-o", "--output", help="Output JSON file")
    imo.add_argument("-v", "--verbose", action="store_true")
    # inspect handles
    ihn = insp_sub.add_parser("handles", parents=[dp],
                              help="List HANDLE_TABLE entries (MSL only)")
    ihn.add_argument("msl_path", help=".msl file path")
    ihn.add_argument("-o", "--output", help="Output JSON file")
    ihn.add_argument("-v", "--verbose", action="store_true")
    # inspect xref
    ixr = insp_sub.add_parser("xref", parents=[dp],
                              help="Resolve cross-references (MSL only)")
    ixr.add_argument("msl_path", help=".msl file path")
    ixr.add_argument("-o", "--output", help="Output JSON file")
    ixr.add_argument("-v", "--verbose", action="store_true")
    # inspect structure
    ist = insp_sub.add_parser("structure", parents=[dp],
                              help="Identify a data structure at an offset")
    ist.add_argument("dump_path", help="Dump or .msl file path")
    ist.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                     help="Offset to overlay structures at (hex or decimal)")
    ist.add_argument("--protocol", default="",
                     help="Restrict candidates to a protocol (default: all)")
    ist.add_argument("-o", "--output", help="Output JSON file")
    ist.add_argument("-v", "--verbose", action="store_true")
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Public alias for sphinx-argparse and external tooling."""
    return _build_parser()


def main():
    """MemDiver CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()
    if args.command is None or args.command == "web":
        sys.exit(_cmd_web(args))
    if args.command == "ui":
        sys.exit(_cmd_ui(args))
    _setup_logging(getattr(args, "verbose", False))
    handlers = {
        "analyze": _cmd_analyze, "scan": _cmd_scan, "batch": _cmd_batch,
        "mcp": _cmd_mcp, "import": _cmd_import, "import-dir": _cmd_import_dir,
        "consensus": _cmd_consensus, "export": _cmd_export,
        "verify": _cmd_verify, "experiment": _cmd_experiment,
        "consensus-begin": _cmd_consensus_begin,
        "consensus-add": _cmd_consensus_add,
        "consensus-finalize": _cmd_consensus_finalize,
        "search-reduce": _cmd_search_reduce,
        "analyze-candidates": _cmd_analyze_candidates,
        "brute-force": _cmd_brute_force,
        "n-sweep": _cmd_n_sweep,
        "auto-floor": _cmd_auto_floor,
        "emit-plugin": _cmd_emit_plugin,
        "export-keylog": _cmd_export_keylog,
        "inspect-pcap": _cmd_inspect_pcap,
        "gen-kem-key": _cmd_gen_kem_key,
        "inspect": _cmd_inspect,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    # BACKSTOP: a CapabilityError propagating out of ANY handler is translated
    # here into a single stderr line + category exit code, so it never escapes
    # as a traceback. Handlers that already present their own errors and return
    # an exit code (e.g. the inspect handlers, which catch CapabilityError in
    # _present_inspect_cli_call) never reach this except clause.
    try:
        sys.exit(handler(args))
    except CapabilityError as e:
        sys.exit(to_cli_exit(e))


if __name__ == "__main__":
    main()
