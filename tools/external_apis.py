"""Legacy compatibility shim for the old single-file bot tools package.

The production platform now uses core.api_manager plus osint collectors.
This module intentionally references only the approved API names:
SERPAPI_KEY, GOOGLE_API_KEY, GOOGLE_CSE_ID, IPINFO_TOKEN, SHODAN_API_KEY,
ABSTRACT_API_KEY and VT_API_KEY.
"""

from __future__ import annotations

import os
from typing import Any


APPROVED_API_ENV_VARS = (
    "SERPAPI_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_CSE_ID",
    "IPINFO_TOKEN",
    "SHODAN_API_KEY",
    "ABSTRACT_API_KEY",
    "VT_API_KEY",
)


def api_status() -> dict[str, bool]:
    return {name: bool(os.getenv(name)) for name in APPROVED_API_ENV_VARS}


def enrich_with_external_apis(report: Any) -> Any:
    """No-op compatibility entrypoint for old report objects.

    New enrichment is implemented in osint.collectors through core.api_manager.
    Keeping this no-op prevents accidental imports from crashing while avoiding
    unsupported API providers.
    """

    if hasattr(report, "metadata") and isinstance(report.metadata, dict):
        report.metadata["approved_api_status"] = api_status()
    return report
