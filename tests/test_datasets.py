"""Tests for Basilisk dataset loading."""

from basilisk.datasets import load_bundled


class TestDatasets:
    def test_sqli_loads(self):
        data = load_bundled("sqli")
        assert isinstance(data, list)
        assert len(data) >= 8
        assert all(isinstance(d, str) for d in data)

    def test_xss_loads(self):
        data = load_bundled("xss")
        assert isinstance(data, list)
        assert len(data) >= 3

    def test_cmdi_loads(self):
        data = load_bundled("cmdi")
        assert isinstance(data, list)
        assert len(data) >= 5

    def test_path_traversal_loads(self):
        data = load_bundled("path_traversal")
        assert isinstance(data, list)
        assert len(data) >= 5

    def test_ssti_loads(self):
        data = load_bundled("ssti")
        assert isinstance(data, list)
        assert len(data) >= 5

    def test_ssrf_loads(self):
        data = load_bundled("ssrf")
        assert isinstance(data, list)
        assert len(data) >= 5

    def test_open_redirect_loads(self):
        data = load_bundled("open_redirect")
        assert isinstance(data, list)
        assert len(data) >= 5

    def test_lfi_loads(self):
        data = load_bundled("lfi")
        assert isinstance(data, list)
        assert len(data) >= 5

    def test_nosqli_loads(self):
        data = load_bundled("nosqli")
        assert isinstance(data, list)
        assert len(data) >= 5

    def test_missing_dataset_raises(self):
        import pytest
        with pytest.raises(FileNotFoundError):
            load_bundled("nonexistent_dataset")
