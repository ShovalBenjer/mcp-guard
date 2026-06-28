"""Guards against version drift across the package metadata."""
import tomllib
from pathlib import Path

import mcp_guard


def test_version_matches_pyproject():
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert mcp_guard.__version__ == data["project"]["version"], (
        "mcp_guard.__version__ and pyproject [project].version must match"
    )
