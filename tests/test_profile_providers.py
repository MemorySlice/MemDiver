"""ProfileProvider chain (plan T1.4): order, caching, and graceful misses."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from memdiver.core.image import profiles
from memdiver.core.image.context import file_sha256
from memdiver.core.install_hints import OPTIONAL_EXTRAS
from memdiver.core.service_errors import CapabilityError, ErrorCategory

BANNER = b"Linux version 6.1.0-test (gcc) #1 SMP Mon Jan 1 00:00:00 UTC 2024\n"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def image(tmp_path) -> Path:
    path = tmp_path / "dump.lime"
    path.write_bytes(b"\x00" * 4096 + BANNER + b"\x00" * 4096)
    return path


class _Stub:
    def __init__(self, name, hit=None):
        self.name, self._hit, self.calls = name, hit, 0

    def resolve(self, image_path, image_sha256):
        self.calls += 1
        return self._hit


def _res(tmp_path, origin="explicit"):
    isf = tmp_path / f"{origin}.json"
    isf.write_text("{}")
    return profiles.ProfileResolution(isf, "abc", origin)


def _fake_pakunoda(calls, success=True, loadable=True):
    mod = types.ModuleType("pakunoda")
    mod.__version__ = "9.9.9"

    def extract_isf(path, arch="auto", **kw):
        calls.append((path, arch))
        loadability = types.SimpleNamespace(loadable=loadable, reason="broken gate")
        return types.SimpleNamespace(
            success=success, isf_json={"metadata": {}} if success else None,
            banner_bytes=BANNER, kernel_version="6.1.0-test", loadability=loadability,
            errors=["boom"])
    mod.extract_isf = extract_isf
    return mod


def test_image_is_an_optional_extra():
    assert "image" in OPTIONAL_EXTRAS


def test_chain_first_hit_wins_and_order(tmp_path, image):
    a, b, c = _Stub("a"), _Stub("b", _res(tmp_path)), _Stub("c", _res(tmp_path))
    chain = profiles.ProfileChain([a, b, c])
    assert chain.resolve(image, "sha").origin == "explicit"
    assert (a.calls, b.calls, c.calls) == (1, 1, 0)
    assert chain.attempts == [("a", "miss: no profile"), ("b", "hit")]


def test_default_chain_order():
    names = [p.name for p in profiles.default_chain().providers]
    assert names == ["explicit", "cache", "draft", "pakunoda", "vol3"]


def test_all_miss_raises_listing_providers(tmp_path, image):
    chain = profiles.ProfileChain([_Stub("alpha"), _Stub("beta")])
    with pytest.raises(CapabilityError) as err:
        chain.resolve(image, "sha")
    assert err.value.category is ErrorCategory.UNSUPPORTED
    assert "alpha" in str(err.value) and "beta" in str(err.value)


def test_explicit_provider_hashes(tmp_path, image):
    isf = tmp_path / "k.json"
    isf.write_text('{"a": 1}')
    hit = profiles.ExplicitProvider(isf).resolve(image, "sha")
    assert hit.sha256 == file_sha256(isf) and hit.origin == "explicit"
    ref = hit.to_profile_ref()
    assert (ref.isf, ref.sha256, ref.origin) == (str(isf), hit.sha256, "explicit")
    assert profiles.ExplicitProvider(None).resolve(image, "sha") is None
    assert profiles.ExplicitProvider(tmp_path / "nope").resolve(image, "sha") is None


def test_pakunoda_writes_cache_then_cache_serves(monkeypatch, image):
    calls: list = []
    monkeypatch.setitem(sys.modules, "pakunoda", _fake_pakunoda(calls))
    chain = profiles.ProfileChain([profiles.CacheProvider(), profiles.PakunodaLinuxProvider()])
    first = chain.resolve(image, "imgsha")
    assert first.origin == "pakunoda" and len(calls) == 1
    assert first.banner.startswith("Linux version 6.1.0-test")
    prov = json.loads((first.isf_path.parent / "provenance.json").read_text())
    assert prov["pakunoda_version"] == "9.9.9" and prov["kernel_version"] == "6.1.0-test"
    second = chain.resolve(image, "imgsha")
    assert second.origin == "cache" and len(calls) == 1
    assert second.isf_path == first.isf_path
    assert second.details["cached_origin"] == "pakunoda"


def test_pakunoda_missing_returns_none_with_reason(monkeypatch, image):
    monkeypatch.setitem(sys.modules, "pakunoda", None)  # import raises ImportError
    provider = profiles.PakunodaLinuxProvider()
    assert provider.resolve(image, "sha") is None
    assert "not installed" in provider.last_reason


@pytest.mark.parametrize("kw,needle", [({"success": False}, "boom"),
                                       ({"loadable": False}, "broken gate")])
def test_pakunoda_unusable_result_is_a_miss_and_not_cached(monkeypatch, image, kw, needle):
    monkeypatch.setitem(sys.modules, "pakunoda", _fake_pakunoda([], **kw))
    provider = profiles.PakunodaLinuxProvider()
    assert provider.resolve(image, "sha") is None
    assert needle in provider.last_reason
    assert profiles.CacheProvider().resolve(image, "sha") is None


def test_draft_provider_is_a_stub(image):
    assert profiles.DraftProvider().resolve(image, "sha") is None


def test_vol3_provider_miss_returns_none(image):
    provider = profiles.Vol3SymbolDirProvider()
    assert provider.resolve(image, "sha") is None
    assert provider.last_reason


def test_vol3_provider_matches_banner(monkeypatch, tmp_path, image):
    isf = tmp_path / "linux.json"
    isf.write_text("{}")
    manager = types.SimpleNamespace(get_identifier_dictionary=lambda **kw: {
        BANNER: isf.as_uri(), b"Linux version other\n": "file:///nope"})
    sc = types.ModuleType("volatility3.framework.automagic.symbol_cache")
    sc.load_cache_manager = lambda: manager
    monkeypatch.setattr("volatility3.framework.automagic.symbol_cache.load_cache_manager",
                        sc.load_cache_manager)
    hit = profiles.Vol3SymbolDirProvider().resolve(image, "sha")
    assert hit is not None and hit.origin == "vol3" and hit.isf_path == isf


def test_scan_linux_banners(image):
    assert profiles.scan_linux_banners(image) == [BANNER.rstrip(b"\n")]


def test_plausible_banners_first_puts_real_kernel_banner_ahead_of_source_strings():
    """Found on the alma-9 LiME: the first two hits were C comments, not the banner."""
    from memdiver.core.image.profiles import plausible_banners_first
    comment = b"Linux version of this file.  */"
    fmt = b"Linux version %d.%d.%d"
    real = (b"Linux version 5.14.0-611.45.1.el9_7.x86_64 (mockbuild@x64) "
            b"(gcc 11.5.0) #1 SMP PREEMPT_DYNAMIC")
    assert plausible_banners_first([comment, fmt, real]) == [real, comment, fmt]
    assert plausible_banners_first([comment, fmt]) == [comment, fmt]
