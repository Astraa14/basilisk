"""Tests for Basilisk payload generators."""

from basilisk.generator import StaticGenerator, PayloadGenerator


class TestStaticGenerator:
    def setup_method(self):
        self.gen = StaticGenerator()

    def test_sqli_payloads_exist(self):
        payloads = self.gen.payloads_for("sqli")
        assert len(payloads) > 0
        assert all(isinstance(p, str) for p in payloads)

    def test_xss_payloads_exist(self):
        payloads = self.gen.payloads_for("xss")
        assert len(payloads) > 0
        assert all(isinstance(p, str) for p in payloads)

    def test_cmdi_payloads_exist(self):
        payloads = self.gen.payloads_for("cmdi")
        assert len(payloads) > 0

    def test_path_traversal_payloads_exist(self):
        payloads = self.gen.payloads_for("path_traversal")
        assert len(payloads) > 0

    def test_ssti_payloads_exist(self):
        payloads = self.gen.payloads_for("ssti")
        assert len(payloads) > 0

    def test_ssrf_payloads_exist(self):
        payloads = self.gen.payloads_for("ssrf")
        assert len(payloads) > 0

    def test_open_redirect_payloads_exist(self):
        payloads = self.gen.payloads_for("open_redirect")
        assert len(payloads) > 0

    def test_lfi_payloads_exist(self):
        payloads = self.gen.payloads_for("lfi")
        assert len(payloads) > 0

    def test_nosqli_payloads_exist(self):
        payloads = self.gen.payloads_for("nosqli")
        assert len(payloads) > 0

    def test_login_uses_sqli(self):
        payloads = self.gen.payloads_for("login")
        assert len(payloads) > 0
        # login should reuse sqli payloads
        sqli = self.gen.payloads_for("sqli")
        assert payloads == sqli

    def test_unknown_kind_raises(self):
        import pytest
        with pytest.raises(ValueError):
            self.gen.payloads_for("unknown")

    def test_custom_dataset_merges(self, tmp_path):
        custom = tmp_path / "custom.json"
        custom.write_text('["custom_payload_1", "custom_payload_2"]')
        gen = StaticGenerator(custom_dataset=str(custom))
        sqli = gen.payloads_for("sqli")
        assert "custom_payload_1" in sqli
        assert "custom_payload_2" in sqli


class TestPayloadGenerator:
    def test_static_mode_returns_seeds(self):
        gen = PayloadGenerator(use_llm=False)
        payloads = gen.generate("sqli")
        assert len(payloads) > 0

    def test_static_mode_no_form_context(self):
        gen = PayloadGenerator(use_llm=False)
        payloads = gen.generate("xss")
        assert len(payloads) > 0

    def test_llm_mode_without_form_returns_seeds(self):
        gen = PayloadGenerator(use_llm=True)
        payloads = gen.generate("sqli", form_context=None)
        assert len(payloads) > 0
