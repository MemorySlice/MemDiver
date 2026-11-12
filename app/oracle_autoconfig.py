"""Derive a bundled oracle example's config from the dumps already selected.

A BYO oracle example ships a `.toml` template with a hole in it: the gocryptfs
one needs ``sample_ciphertext``, "a file encrypted by the same gocryptfs
instance whose master key we're recovering". In the web wizard the analyst has
already pointed at the dumps of that instance, and the corpus declares the
vault right beside them (``meta.json``'s ``vault_cipher_dir``), so asking the
analyst to retype an absolute path is asking them to restate something the
dataset already knows.

This module reads the example's reserved ``[memdiver]`` table -- automation
metadata that is NOT part of the oracle's own config -- and turns it into a
suggestion the presenter can prefill. Two measured facts shape every decision
here:

1. **Only ``source_paths[0]`` is ever verified.** ``engine/nsweep.py:165-167``
   binds ``reference = sources[0].read_all()[:size]`` once, outside the N loop,
   and every hit's key bytes are sliced out of that one array
   (``engine/brute_force.py:628-634``); the web pipeline likewise caches
   ``reference_bytes`` from the first folded source
   (``app/pipeline/pipeline_runner.py:278,297``). Each corpus run has its own
   password and therefore its own master key, so a ciphertext taken from any
   run but the first dump's would decrypt under a key that is never a candidate:
   zero hits, no error, no clue why. The reference run is the ONLY run whose
   vault may be used, and a selection spanning several runs is warned about
   rather than silently averaged.

2. **The bundled gocryptfs oracle is AES-only.** It hardcodes AES-256-GCM
   (``CONTENT_KEY_INFO = b"AES-GCM file content encryption"``), while 47 of the
   95 corpus runs are ``xchacha`` -- it raises ``InvalidTag`` for every one of
   them (the paper's "cipher-mode mismatch -> INCONCLUSIVE"). Prefilling a
   ciphertext for an xchacha run would manufacture a run that fails everywhere,
   and that failure is indistinguishable from "the key is not in this dump".
   So a declared ``requires_cipher`` that the run does not match blocks the
   suggestion outright and says so, instead of handing back a config that is
   guaranteed to lie.

Nothing here raises: an absent ``meta.json``, an undeclared vault, an
unreadable directory or an unknown strategy all mean "nothing to suggest", and
the analyst simply fills the field by hand as before.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from memdiver.core.dataset_metadata import DatasetMeta
from memdiver.core.discovery import RunDiscovery
from memdiver.engine.oracle import RESERVED_CONFIG_TABLE, load_oracle_config

logger = logging.getLogger("memdiver.app.oracle_autoconfig")

#: Table name an example's `.toml` reserves for memdiver's own automation. It
#: is stripped before the rest of the template reaches the oracle, so an oracle
#: never sees -- and can never collide with -- this key.
#: Re-exported so callers keep one spelling; the table name is owned by
#: ``engine.oracle``, which is what actually strips it before user code runs.
RESERVED_TABLE = RESERVED_CONFIG_TABLE

#: The only autofill strategy implemented today: "the one encrypted file in the
#: run's declared gocryptfs vault". Any other value is data from a file we did
#: not write, so it is ignored rather than trusted.
VAULT_CONTENT_FILE = "vault_content_file"


@dataclass(frozen=True)
class AutofillRule:
    """How to fill ONE config key from the reference run."""

    strategy: str
    exclude: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ExampleAutomation:
    """The parsed ``[memdiver]`` table of an example's `.toml`."""

    requires_cipher: Optional[str] = None
    autofill: Dict[str, AutofillRule] = field(default_factory=dict)


@dataclass
class ConfigSuggestion:
    """What the wizard may prefill, and what it must tell the analyst.

    ``config`` empty with no ``blocked_reason`` means only "nothing derivable" --
    the ordinary outcome for a dump outside the corpus. ``blocked_reason`` is
    the louder case: the run IS known and this oracle cannot verify it at all.
    """

    config: Dict[str, Any] = field(default_factory=dict)
    provenance: Optional[str] = None
    blocked_reason: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    reference_run: Optional[str] = None
    reference_dump: Optional[str] = None


def split_reserved(template: dict) -> Tuple[dict, dict]:
    """Split a loaded template into (oracle config, memdiver automation).

    The oracle receives the first half only. Keeping the automation inside the
    same file -- rather than in a parallel sidecar -- means an example and its
    autofill rules cannot be shipped out of sync with each other.
    """
    reserved = template.get(RESERVED_TABLE)
    config = {key: value for key, value in template.items() if key != RESERVED_TABLE}
    return config, dict(reserved) if isinstance(reserved, dict) else {}


def load_example_automation(toml_path: Path) -> ExampleAutomation:
    """Read the ``[memdiver]`` table of ``toml_path``; empty when there is none."""
    try:
        template = load_oracle_config(Path(toml_path))
    except Exception as exc:  # unreadable, absent, or not valid TOML
        logger.debug("No automation for %s: %s", toml_path, exc)
        return ExampleAutomation()
    _, reserved = split_reserved(template)
    return _parse_automation(reserved)


def suggest_example_config(
    example_path: Path, source_paths: Sequence[str]
) -> ConfigSuggestion:
    """Suggest config values for ``example_path`` from the selected dumps.

    Never raises: every failure mode collapses to an empty suggestion, because
    a wizard that cannot prefill a field is in exactly the state it was in
    before this feature existed, while a wizard that 500s is not.
    """
    try:
        return _suggest(Path(example_path), source_paths)
    except Exception:  # pragma: no cover - defence, not a code path
        logger.debug("Config suggestion failed for %s", example_path, exc_info=True)
        return ConfigSuggestion()


# -- Internals ----------------------------------------------------------------


def _parse_automation(reserved: dict) -> ExampleAutomation:
    """Build an :class:`ExampleAutomation` from the raw reserved table."""
    required = reserved.get("requires_cipher")
    raw_rules = reserved.get("autofill")
    rules = raw_rules if isinstance(raw_rules, dict) else {}
    return ExampleAutomation(
        requires_cipher=str(required) if required else None,
        autofill={
            str(key): _parse_rule(spec)
            for key, spec in rules.items()
            if isinstance(spec, dict)
        },
    )


def _parse_rule(spec: dict) -> AutofillRule:
    """Build one :class:`AutofillRule`; an absent strategy stays unmatchable."""
    excluded = spec.get("exclude")
    excluded = excluded if isinstance(excluded, (list, tuple)) else ()
    return AutofillRule(
        strategy=str(spec.get("strategy", "")),
        exclude=tuple(str(name) for name in excluded),
    )


def _suggest(example_path: Path, source_paths: Sequence[str]) -> ConfigSuggestion:
    """The body of :func:`suggest_example_config`, free to raise."""
    automation = load_example_automation(example_path.with_suffix(".toml"))
    if not source_paths:
        return ConfigSuggestion()

    reference_dump = str(source_paths[0])
    meta = RunDiscovery.meta_for_dump(reference_dump)
    if meta is None:
        logger.debug("No meta.json owns %s; nothing to suggest", reference_dump)
        return ConfigSuggestion(reference_dump=reference_dump)

    suggestion = ConfigSuggestion(
        reference_dump=reference_dump, reference_run=meta.run_id
    )
    _warn_on_mixed_runs(source_paths, meta, suggestion)

    mismatch = _cipher_mismatch(automation.requires_cipher, meta)
    if mismatch is not None:
        suggestion.blocked_reason = mismatch
        return suggestion

    _apply_autofill(automation, meta, suggestion)
    if suggestion.config:
        suggestion.provenance = _provenance(meta, reference_dump)
    return suggestion


def _run_label(meta: DatasetMeta) -> str:
    """How a run is named to the analyst: its DIRECTORY, not its ``run_id``.

    ``meta.run_id`` is ``"1"`` where the directory the analyst actually browsed
    and selected dumps from is ``run_0001``. Every message here agrees on the
    directory name so a warning can be matched against the file picker without
    the reader doing arithmetic.
    """
    return meta.source_path.parent.name or f"run {meta.run_id}"


def _provenance(meta: DatasetMeta, reference_dump: str) -> str:
    """The one-line answer to "where did this value come from?"."""
    return (
        f"the vault beside {_run_label(meta)}/{Path(reference_dump).name}, "
        f"the first of the dumps you selected"
    )


def _cipher_mismatch(required: Optional[str], meta: DatasetMeta) -> Optional[str]:
    """Explain why this oracle cannot verify this run, or ``None`` if it can.

    Kept as the in-module spelling every call site here already uses; the
    sentence itself lives in :func:`cipher_mismatch_reason` so a second caller
    cannot drift a word away from it.
    """
    return cipher_mismatch_reason(required, meta)


def cipher_mismatch_reason(required: Optional[str], meta: DatasetMeta) -> Optional[str]:
    """Explain why an oracle requiring *required* cannot verify *meta*'s run.

    ``None`` means "no objection": either the oracle declares no cipher
    requirement, or the run does not declare its cipher (nothing to contradict),
    or the two agree.

    Public because the same judgement is needed wherever a run meets an oracle
    that only speaks one cipher — :mod:`app.oracle_smoke_test` raises it as a
    caveat on its positive control, because a key the oracle is structurally
    unable to accept turns "the oracle rejected the real key" from a failing
    grade into an expected outcome, and the analyst must be told which of the
    two they are looking at.
    """
    if not required or not meta.cipher:
        return None
    if meta.cipher.strip().casefold() == required.strip().casefold():
        return None
    return (
        f"{_run_label(meta)} was captured with the {meta.cipher} cipher, but "
        f"this oracle only decrypts {required}. It would report every key "
        f"candidate as a failure, so this run cannot be verified by it at all — "
        f"a rejection would mean nothing about whether the key is in the dump. "
        f"Select a run captured with {required}, or use an oracle that speaks "
        f"{meta.cipher}."
    )


def _warn_on_mixed_runs(
    source_paths: Sequence[str], reference: DatasetMeta, suggestion: ConfigSuggestion
) -> None:
    """Say out loud that a multi-run selection uses ONE run's vault (fact 1)."""
    run_ids = {
        meta.run_id
        for meta in (RunDiscovery.meta_for_dump(path) for path in source_paths)
        if meta is not None
    }
    if len(run_ids) < 2:
        return
    suggestion.warnings.append(
        f"The selected dumps span {len(run_ids)} runs, and each run has its own "
        f"password and master key. Only the first dump is verified against, so "
        f"this value comes from {_run_label(reference)}'s vault."
    )


def _apply_autofill(
    automation: ExampleAutomation, meta: DatasetMeta, suggestion: ConfigSuggestion
) -> None:
    """Fill every config key whose rule the reference run can satisfy."""
    for key, rule in automation.autofill.items():
        if rule.strategy != VAULT_CONTENT_FILE:
            logger.debug(
                "Ignoring unknown autofill strategy %r for %r", rule.strategy, key
            )
            continue
        content_file, warning = _vault_content_file(meta, rule)
        if warning is not None:
            suggestion.warnings.append(warning)
        if content_file is not None:
            suggestion.config[key] = str(content_file)


def _vault_content_file(
    meta: DatasetMeta, rule: AutofillRule
) -> Tuple[Optional[Path], Optional[str]]:
    """The single encrypted file in the run's vault, or a reason there is none.

    Exactly one candidate is the only answer worth prefilling. Two files means
    two possible ciphertexts, and picking one by sort order would put a value in
    front of the analyst that looks derived but was guessed -- so the field is
    left empty and the directory is named, which is what they need to choose.
    """
    vault = meta.vault_dir()
    if vault is None:
        return None, None
    try:
        entries = sorted(vault.iterdir())
    except OSError as exc:
        logger.debug("Cannot list vault %s: %s", vault, exc)
        return None, None

    candidates = [entry for entry in entries if _is_content_file(entry, rule.exclude)]
    if len(candidates) == 1:
        return candidates[0], None
    return None, (
        f"Found {len(candidates)} encrypted files in {vault}, so no ciphertext "
        f"was filled in — name one of them yourself."
    )


def _is_content_file(entry: Path, exclude: Sequence[str]) -> bool:
    """True for a plain, non-hidden vault file that is not gocryptfs metadata."""
    return (
        entry.is_file()
        and not entry.name.startswith(".")
        and entry.name not in exclude
    )


# -- Format-oracle suggestion ---------------------------------------------------
#
# "Which of the shipped format oracles (memdiver.oracles.formats) fits this
# dump, and with what evidence?" Three signals, strongest first; the first one
# that names a kind wins and its reason travels with the suggestion, so the
# analyst always sees WHY a kind was picked. None of them is a guess: a dump
# that matches nothing gets ``None`` plus the reason nothing matched.
#
# 1. the run's ``meta.json`` declares a gocryptfs vault -> gocryptfs-gcm, with
#    one of the vault's own encrypted files as the sample (high confidence);
# 2. an ``.msl`` KEY_HINT block names a key type / protocol / note we map;
# 3. the process identity (exe, command line) or the module list names a
#    program we map (the exe is empty in many real captures, so the modules --
#    e.g. ``libssh.so.4`` -- carry most of the weight).

#: Program / library basename (lower-case, version suffix stripped) -> kind.
_PROGRAM_KINDS: Dict[str, str] = {
    "gocryptfs": "gocryptfs-gcm",
    "wireguard-go": "x25519-pubkey",
    "tailscaled": "x25519-pubkey",
    "sshd": "ssh-kdf-consistency",
    "ssh": "ssh-kdf-consistency",
    "dropbear": "ssh-kdf-consistency",
    "dbclient": "ssh-kdf-consistency",
    "libssh": "ssh-kdf-consistency",
    "libssh2": "ssh-kdf-consistency",
    "libwolfssh": "ssh-kdf-consistency",
    "cryptsetup": "luks",
    "veracrypt": "xts-fsmagic",
}

#: MSL KEY_HINT key-type / protocol names (spec Table 17) -> kind. TLS-family
#: protocols are deliberately absent: format oracles never verify traffic keys.
_HINT_KEY_TYPES: Dict[str, str] = {
    "SSH_SESSION_KEY": "ssh-kdf-consistency",
    "WIREGUARD_KEY": "x25519-pubkey",
}
_HINT_PROTOCOLS: Dict[str, str] = {
    "SSH": "ssh-kdf-consistency",
    "WIREGUARD": "x25519-pubkey",
}
#: Words in a KEY_HINT note -> kind (checked in this order).
_HINT_NOTE_WORDS: Tuple[Tuple[str, str], ...] = (
    ("gocryptfs", "gocryptfs-gcm"),
    ("luks", "luks"),
    ("dm-crypt", "luks"),
    ("veracrypt", "xts-fsmagic"),
    ("wireguard", "x25519-pubkey"),
    ("ssh", "ssh-kdf-consistency"),
)
_HINT_CONFIDENCE = {0: "low", 1: "medium", 2: "high"}

#: What each kind needs as evidence when no sample could be derived.
_SAMPLE_NEEDS: Dict[str, str] = {
    "gocryptfs-gcm": "one encrypted file of the vault (its directory holds gocryptfs.conf)",
    "luks": "the LUKS header of the volume (the first 4 KiB for LUKS1, 32 KiB for LUKS2)",
    "xts-fsmagic": "the first ciphertext bytes of the encrypted volume's data area",
    "x25519-pubkey": "the 32-byte public key (optional: none when the plugin finds it)",
}


@dataclass
class FormatSuggestion:
    """A format oracle that fits a dump, and why. ``sample_path`` may be ``None``."""

    kind: str
    reason: str
    confidence: str
    sample_path: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    signal: str = ""
    sample_needed: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "sample_path": self.sample_path,
            "params": dict(self.params),
            "reason": self.reason,
            "confidence": self.confidence,
            "signal": self.signal,
            "sample_needed": self.sample_needed,
        }


def suggest_format_oracle(
    dump_path: "str | Path",
) -> Tuple[Optional[FormatSuggestion], str]:
    """Suggest the format oracle for *dump_path*: ``(suggestion, reason)``.

    ``suggestion`` is ``None`` when no signal names a kind; ``reason`` then
    says what was looked at. Never raises on unreadable inputs -- each signal
    that cannot be read is skipped and named in the reason.
    """
    path = Path(dump_path).expanduser()
    looked: List[str] = []
    for signal in (_suggest_from_vault, _suggest_from_key_hints, _suggest_from_identity):
        try:
            suggestion, note = signal(path)
        except Exception as exc:  # noqa: BLE001 - one unreadable signal must not hide the next
            logger.debug("format suggestion signal %s failed: %r", signal.__name__, exc)
            suggestion, note = None, f"{signal.__name__.removeprefix('_suggest_from_')}: unreadable ({exc})"
        if suggestion is not None:
            if suggestion.sample_path is None:
                suggestion.sample_needed = _SAMPLE_NEEDS.get(suggestion.kind)
            return suggestion, suggestion.reason
        looked.append(note)
    return None, "no format oracle fits this dump: " + "; ".join(looked)


def _suggest_from_vault(path: Path) -> Tuple[Optional[FormatSuggestion], str]:
    meta = RunDiscovery.meta_for_dump(path)
    if meta is None:
        return None, "no meta.json owns this dump"
    vault = meta.vault_dir()
    if vault is None:
        return None, f"{_run_label(meta)}/meta.json declares no gocryptfs vault"
    where = f"{_run_label(meta)}/meta.json declares the gocryptfs vault {vault}"
    content_file = _vault_content_file_for_sample(vault)
    if content_file is None:
        return FormatSuggestion(
            kind="gocryptfs-gcm", confidence="medium", signal="vault",
            reason=f"{where}, but no encrypted file in it could be packed as a sample",
        ), ""
    # The vault DIRECTORY is the sample: both the BYO bridge and plugin
    # synthesis pack it with gocryptfs.conf (a lone content file would lose
    # the FeatureFlags in the synthesis path).
    return FormatSuggestion(
        kind="gocryptfs-gcm", confidence="high", signal="vault",
        sample_path=str(vault),
        reason=(f"{where}; sample = the vault (its encrypted file "
                f"{Path(content_file).name} + gocryptfs.conf FeatureFlags), "
                f"cipher {meta.cipher or 'from the conf'}"),
    ), ""


def _vault_content_file_for_sample(vault: Path) -> Optional[str]:
    """The content file the gocryptfs format packs from *vault*, or ``None``."""
    from memdiver.engine.resources.format_oracle import format_module, load_format_sample

    try:
        load_format_sample("gocryptfs-gcm", vault)
        return str(format_module("gocryptfs-gcm").find_content_file(str(vault)))
    except (OSError, ValueError):
        return None


def _is_msl(path: Path) -> bool:
    from memdiver.msl.enums import FILE_MAGIC

    if not path.is_file():
        return False
    with path.open("rb") as handle:
        return handle.read(len(FILE_MAGIC)) == FILE_MAGIC


def _msl_blocks(path: Path, collector: str) -> list:
    from memdiver.msl.reader import MslReader

    with MslReader(path) as reader:
        return list(getattr(reader, collector)())


def _suggest_from_key_hints(path: Path) -> Tuple[Optional[FormatSuggestion], str]:
    if not _is_msl(path):
        return None, "not an .msl (no KEY_HINT blocks)"
    hints = _msl_blocks(path, "collect_key_hints")
    for hint in hints:
        kind, why = _hint_kind(hint)
        if kind is not None:
            return FormatSuggestion(
                kind=kind, signal="key_hint",
                confidence=_HINT_CONFIDENCE.get(int(hint.confidence), "low"),
                reason=f"KEY_HINT block: {why}",
            ), ""
    return None, f"{len(hints)} KEY_HINT block(s), none naming a format oracle"


def _enum_name(enum_cls: Any, value: int) -> str:
    try:
        return enum_cls(int(value)).name
    except ValueError:
        return f"0x{int(value):04x}"


def _hint_kind(hint: Any) -> Tuple[Optional[str], str]:
    from memdiver.msl.enums import MslKeyType, MslProtocol

    key_type = _enum_name(MslKeyType, hint.key_type)
    if key_type in _HINT_KEY_TYPES:
        return _HINT_KEY_TYPES[key_type], f"key_type {key_type}"
    protocol = _enum_name(MslProtocol, hint.protocol)
    if protocol in _HINT_PROTOCOLS:
        return _HINT_PROTOCOLS[protocol], f"protocol {protocol}"
    note = (hint.note or "").casefold()
    for word, kind in _HINT_NOTE_WORDS:
        if word in note:
            return kind, f"note mentions {word!r}"
    return None, ""


def program_basename(path_or_name: str) -> str:
    """``/lib/x/libssh.so.4`` -> ``libssh``; ``/usr/bin/gocryptfs`` -> ``gocryptfs``."""
    name = Path(str(path_or_name).strip().split(" ", 1)[0]).name.casefold()
    if ".so" in name:
        name = name.split(".so", 1)[0]
    return name


def _suggest_from_identity(path: Path) -> Tuple[Optional[FormatSuggestion], str]:
    if not _is_msl(path):
        return None, "not an .msl (no process identity or module list)"
    names: List[Tuple[str, str]] = []
    for ident in _msl_blocks(path, "collect_process_identity"):
        names += [("exe", ident.exe_path), ("command line", ident.cmd_line)]
    names += [("module", module.path) for module in _msl_blocks(path, "collect_modules")]
    for source, value in names:
        kind = _PROGRAM_KINDS.get(program_basename(value)) if value else None
        if kind is not None:
            return FormatSuggestion(
                kind=kind, signal="process", confidence="medium",
                reason=f"the process {source} is {value!r} ({program_basename(value)} -> {kind})",
            ), ""
    return None, f"no known program among {len(names)} process names (exe, command line, modules)"
