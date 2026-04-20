"""Selection control panel for protocol version, scenario, library, phase."""

import logging
from typing import Any, List, Tuple

logger = logging.getLogger("memdiver.ui.controls.selector")


def create_protocol_dropdown(mo, dataset_info) -> Any:
    """Create protocol name dropdown from discovered protocols."""
    if dataset_info and dataset_info.protocols_info:
        protocols = sorted(dataset_info.protocols_info.keys())
    else:
        protocols = ["TLS"]
    return mo.ui.dropdown(
        options=protocols,
        value=protocols[0] if protocols else "TLS",
        label="Protocol",
    )


def create_selector_controls(
    mo,
    dataset_info,
    protocol_versions: List[str] = None,
    protocol_name: str = None,
) -> Tuple:
    """Create the protocol version selector dropdown.

    Args:
        mo: The marimo runtime module (passed at runtime, not imported).
        dataset_info: A DatasetInfo instance from DatasetScanner, or None.
        protocol_versions: Optional explicit list of protocol versions to offer.

    Returns:
        Tuple of (protocol_version_dropdown,).
    """
    versions = []
    if protocol_name and dataset_info and dataset_info.protocols_info:
        proto_versions = dataset_info.protocols_info.get(protocol_name, set())
        if proto_versions:
            versions = sorted(proto_versions)
    if not versions:
        if protocol_versions is not None:
            versions = sorted(protocol_versions)
        elif dataset_info is not None:
            versions = sorted(dataset_info.protocol_versions)

    version_dropdown = mo.ui.dropdown(
        options=versions or ["13"],
        value=versions[0] if versions else "13",
        label="Protocol Version",
    )
    return (version_dropdown,)


def create_scenario_dropdown(mo, dataset_info, protocol_version: str):
    """Create scenario dropdown for a specific protocol version.

    Args:
        mo: The marimo runtime module.
        dataset_info: A DatasetInfo instance from DatasetScanner, or None.
        protocol_version: The selected protocol version string (e.g. "13").

    Returns:
        A marimo dropdown element for scenario selection.
    """
    scenarios = (
        dataset_info.scenarios.get(protocol_version, [])
        if dataset_info
        else []
    )
    return mo.ui.dropdown(
        options=scenarios or ["default"],
        value=scenarios[0] if scenarios else "default",
        label="Scenario",
    )


def create_library_controls(
    mo,
    dataset_info,
    protocol_version: str,
    scenario: str,
) -> Tuple:
    """Create library and phase selection controls.

    Args:
        mo: The marimo runtime module.
        dataset_info: A DatasetInfo instance from DatasetScanner, or None.
        protocol_version: The selected protocol version string.
        scenario: The selected scenario name.

    Returns:
        Tuple of (library_multiselect, phase_dropdown, normalize_checkbox,
        max_runs_slider).
    """
    libs = (
        sorted(dataset_info.libraries.get(scenario, set()))
        if dataset_info
        else []
    )

    library_select = mo.ui.multiselect(
        options=libs,
        label="Libraries",
        value=libs[:1] if libs else [],
    )

    # Resolve phases from the first available library
    phases = resolve_phases(dataset_info, protocol_version, scenario, libs)

    phase_dropdown = mo.ui.dropdown(
        options=phases or ["pre_abort"],
        value=phases[0] if phases else "pre_abort",
        label="Phase",
    )
    normalize_cb = mo.ui.checkbox(value=False, label="Normalize phases")
    max_runs = mo.ui.slider(
        start=1,
        stop=20,
        value=10,
        step=1,
        label="Max runs",
    )
    return library_select, phase_dropdown, normalize_cb, max_runs


def resolve_phases(
    dataset_info,
    protocol_version: str,
    scenario: str,
    libs: List[str],
    normalize: bool = False,
) -> List[str]:
    """Look up available phases for the first library in the selection.

    Args:
        dataset_info: A DatasetInfo instance, or None.
        protocol_version: Protocol version string.
        scenario: Scenario name.
        libs: Sorted list of library names.
        normalize: If True, return canonical (normalized) phase names.

    Returns:
        List of phase name strings, possibly empty.
    """
    if not libs or dataset_info is None:
        return []
    lib_key = f"{protocol_version}/{scenario}/{libs[0]}"
    if normalize:
        return dataset_info.normalized_phases.get(lib_key, [])
    return dataset_info.phases.get(lib_key, [])


def render_selector_panel(mo, *controls) -> Any:
    """Render the selector panel layout.

    Args:
        mo: The marimo runtime module.
        *controls: Variable number of UI control elements to display.

    Returns:
        A marimo vstack layout element.
    """
    return mo.vstack([
        mo.md("### Selection"),
        mo.hstack(list(controls), justify="start", gap=1, wrap=True),
    ])
