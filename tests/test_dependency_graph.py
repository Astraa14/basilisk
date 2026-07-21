"""Tests for project dependency graph analysis."""

import json

from basilisk.dependency_graph import analyze_path


def test_analyze_path_scans_package_lock_without_attribute_error(tmp_path):
    lockfile = {
        "packages": {
            "": {"name": "demo"},
            "node_modules/lodash": {"version": "4.17.20"},
        }
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lockfile))

    graph = analyze_path(tmp_path)

    assert graph.total_count == 1
    assert graph.vulnerable_count == 1
    assert graph.nodes[0].name == "lodash"
