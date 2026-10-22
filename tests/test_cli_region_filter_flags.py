"""The analysis-time region view filter flags reach the consensus subcommands."""

import pytest

from memdiver.cli import _build_parser
from memdiver.cli.consensus import region_filter_from_args

_CONSENSUS_COMMANDS = ("consensus", "consensus-window", "consensus-regions")


@pytest.mark.parametrize("command", _CONSENSUS_COMMANDS)
def test_region_flags_default_to_unfiltered(command):
    args = _build_parser().parse_args([command, "a.msl", "b.msl"])
    assert args.regions is None and args.exclude_regions is None
    assert region_filter_from_args(args) is None


@pytest.mark.parametrize("command", _CONSENSUS_COMMANDS)
def test_region_flags_parse_to_a_note(command):
    args = _build_parser().parse_args(
        [command, "a.msl", "b.msl", "--regions", "heap,stack,image",
         "--exclude-regions", "image"])
    assert region_filter_from_args(args) == "regions=heap,stack"


def test_regions_all_means_no_filter():
    args = _build_parser().parse_args(["consensus", "a.msl", "--regions", "all"])
    assert region_filter_from_args(args) is None


def test_unknown_region_category_raises():
    args = _build_parser().parse_args(["consensus", "a.msl", "--regions", "bogus"])
    with pytest.raises(ValueError):
        region_filter_from_args(args)
