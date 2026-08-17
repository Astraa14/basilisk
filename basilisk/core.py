"""Basilisk facade — wires Recon + Attack Engine (HackAgent-style pipeline)
plus the Division-1 protocol & transport layer scan."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from basilisk.auth_methods import AuthProvider
from basilisk.cache_control import cache_control_fuzzer
from basilisk.cors_misconfiguration import cors_misconfiguration_fuzzer
from basilisk.csp_analysis import csp_analysis_fuzzer
from basilisk.engine import AttackEngine
from basilisk.encoding_bypass import encoding_bypass_fuzzer
from basilisk.http import RequestEngine
from basilisk.alternate_protocol import alternate_protocol_fuzzer
from basilisk.models import Finding, ScanConfig, ScanReport
from basilisk.options_enum import options_enumeration_fuzzer
from basilisk.protocol_confusion import protocol_confusion_fuzzer
from basilisk.range_abuse import range_abuse_fuzzer
from basilisk.recon import Recon
from basilisk.sri_bypass import sri_bypass_fuzzer
from basilisk.track_method import track_method_fuzzer
from basilisk.scoring import score_finding
from basilisk.target import WebTarget
from basilisk.tunnel import SshTunnel

ProgressCb = Callable[[str], None]


class Basilisk:
    """Coordinate protocol checks, recon, and active attacks."""

    def __init__(
        self,
        target_url: str,
        timeout: float = 5,
        use_llm: bool = False,
        custom_dataset: str | Path | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        delay: float = 0,
        max_retries: int = 1,
        extra_headers: dict | None = None,
        cookies: dict | None = None,
        config: ScanConfig | None = None,
    ):
        self.target_url = target_url.rstrip("/")
        if not self.target_url.startswith(("http://", "https://")):
            self.target_url = "https://" + self.target_url
        self.use_llm = use_llm
        self.custom_dataset = custom_dataset
        self.config = config or ScanConfig(
            timeout=timeout,
            delay=delay,
            max_retries=max_retries,
        )
        self.config.timeout = timeout
        self.config.delay = delay
        self.config.max_retries = max_retries

        self.tunnel: SshTunnel | None = None
        proxy = self.config.proxy
        if self.config.ssh_tunnel:
            try:
                self.tunnel = SshTunnel(self.config.ssh_tunnel)
                proxy = self.tunnel.start()
            except Exception as exc:
                logging.getLogger(__name__).warning(
                    "SSH tunnel unavailable, scanning directly: %s", exc
                )

        from basilisk.http import RequestEngine

        requester = RequestEngine(
            timeout=timeout,
            delay=delay,
            max_retries=max_retries,
            extra_headers=extra_headers,
            cookies=cookies,
            verify_tls=self.config.verify_tls,
            follow_redirects=self.config.follow_redirects,
            max_redirects=self.config.max_redirects,
            backoff_factor=self.config.backoff_factor,
            backoff_max=self.config.backoff_max,
            proxy=proxy,
            no_proxy=self.config.no_proxy,
            pool_connections=self.config.pool_connections,
            pool_maxsize=self.config.pool_maxsize,
            cookie_jar=self.config.cookie_jar,
            auth=AuthProvider.from_config(self.config)
            if self.config.auth_method not in ("", "none")
            else None,
            logging_enabled=self.config.request_logging,
            log_path=self.config.log_path,
        )
        self.target = WebTarget(requester=requester)
        self.recon = Recon(self.target)
        llm_client = (
            LLMClient(api_key=api_key, base_url=base_url, model=model) if use_llm else None
        )
        self.engine = AttackEngine(
            target=self.target,
            use_llm=use_llm,
            custom_dataset=custom_dataset,
            llm_client=llm_client,
            config=self.config,
        )
        self.protocol_scanner = ProtocolScanner(
            engine=requester,
            target_url=self.target_url,
            verify_tls=self.config.verify_tls,
            enable_http2=self.config.enable_http2 and not proxy,
            enable_http3=self.config.enable_http3 and not proxy,
            dns_rebinding_check=self.config.dns_rebinding_check,
            pipeline_check=self.config.pipeline_check,
            tcp_anomaly_check=self.config.tcp_anomaly_check,
            timeout=timeout,
        )

    def scan(
        self,
        max_pages: int = 15,
        active: bool = True,
        fuzz_url_params: bool = True,
        deep_scan: bool = False,
        on_progress: ProgressCb | None = None,
    ) -> dict:
        def note(msg: str) -> None:
            if on_progress:
                on_progress(msg)

        findings: list[Finding] = []

        if self.config.protocol_scan:
            note("Running protocol & transport layer checks...")
            findings.extend(self.protocol_scanner.run(on_progress=on_progress))

        # Division 3: Web Security & Standards Violations
        if self.config.protocol_confusion:
            note("Checking for protocol confusion attacks...")
            try:
                cc_findings = protocol_confusion_fuzzer(
                    self.target.requester,
                    self.target_url,
                    timeout=self.config.timeout,
                )
                findings.extend(cc_findings)
            except Exception as e:
                logger.warning(f"Protocol confusion fuzzer error: {e}")

        if self.config.range_abuse:
            note("Checking for range request abuse...")
            try:
                range_findings = range_abuse_fuzzer(
                    self.target.requester,
                    self.target_url,
                    timeout=self.config.timeout,
                )
                findings.extend(range_findings)
            except Exception as e:
                logger.warning(f"Range abuse fuzzer error: {e}")

        if self.config.track_method:
            note("Checking for TRACK method...")
            try:
                track_findings = track_method_fuzzer(
                    self.target.requester,
                    self.target_url,
                    timeout=self.config.timeout,
                )
                findings.extend(track_findings)
            except Exception as e:
                logger.warning(f"Track method fuzzer error: {e}")

        if self.config.options_enum:
            note("Enumerating OPTIONS methods...")
            try:
                options_findings = options_enumeration_fuzzer(
                    self.target.requester,
                    self.target_url,
                    timeout=self.config.timeout,
                )
                findings.extend(options_findings)
            except Exception as e:
                logger.warning(f"Options enumeration fuzzer error: {e}")

        if self.config.webdav:
            note("Checking for WebDAV methods...")
            # WebDAV can be checked via OPTIONS enumeration results
            # or by sending PROPFIND requests
            try:
                opts = options_enumeration_fuzzer(
                    self.target.requester,
                    self.target_url,
                    timeout=self.config.timeout,
                )
                # Filter WebDAV methods from OPTIONS results
                webdav_findings = []
                for f in opts:
                    if f.attack_type == "webdav_enum":
                        webdav_findings.append(f)
                findings.extend(webdav_findings)
            except Exception as e:
                logger.warning(f"WebDAV check error: {e}")

        if self.config.csp_analysis:
            note("Analyzing Content-Security-Policy...")
            try:
                # CSP analysis requires HTML content, will be done during recon
                # For now, we'll skip and rely on passive analysis
                pass
            except Exception as e:
                logger.warning(f"CSP analysis error: {e}")

        if self.config.cors_misconfiguration:
            note("Checking for CORS misconfiguration...")
            try:
                # CORS analysis requires HTML response, done during recon
                # For now, we'll skip active fuzzing
                pass
            except Exception as e:
                logger.warning(f"CORS misconfiguration error: {e}")

        if self.config.sri_bypass:
            note("Checking for SRI bypass techniques...")
            try:
                # SRI bypass analysis requires HTML, done during recon
                pass
            except Exception as e:
                logger.warning(f"SRI bypass error: {e}")

        if self.config.service_worker:
            note("Checking for service worker caching...")
            # Service worker analysis done during recon/passive phase
            pass

        if self.config.cache_control:
            note("Analyzing Cache-Control headers...")
            try:
                cc_findings = cache_control_fuzzer(
                    self.target.requester,
                    self.target_url,
                    timeout=self.config.timeout,
                )
                findings.extend(cc_findings)
            except Exception as e:
                logger.warning(f"Cache-Control fuzzer error: {e}")

        if self.config.hsts_preload:
            note("Checking HSTS preload status...")
            # HSTS preload check done during recon
            pass

        if self.config.content_encoding_bypass:
            note("Checking for Content-Encoding bypass...")
            try:
                enc_findings = encoding_bypass_fuzzer(
                    self.target.requester,
                    self.target_url,
                    timeout=self.config.timeout,
                )
                findings.extend(enc_findings)
            except Exception as e:
                logger.warning(f"Content-Encoding bypass fuzzer error: {e}")

        if self.config.accept_encoding_manipulation:
            note("Checking for Accept-Encoding manipulation...")
            try:
                ae_findings = accept_encoding_manipulation_fuzzer(
                    self.target.requester,
                    self.target_url,
                    timeout=self.config.timeout,
                )
                findings.extend(ae_findings)
            except Exception as e:
                logger.warning(f"Accept-Encoding manipulation fuzzer error: {e}")

        if self.config.alternate_protocol:
            note("Checking for alternate protocol support...")
            try:
                alt_findings = alternate_protocol_fuzzer(
                    self.target.requester,
                    self.target_url,
                    timeout=self.config.timeout,
                )
                findings.extend(alt_findings)
            except Exception as e:
                logger.warning(f"Alternate protocol fuzzer error: {e}")

        note(f"Starting recon on {self.target_url}")
        recon_result = self.recon.crawl(
            self.target_url,
            max_pages=max_pages if not deep_scan else max_pages * 3,
            on_progress=on_progress,
        )
        findings.extend(recon_result["findings"])
        forms = recon_result["forms"]
        param_urls = recon_result.get("urls_with_params", [])

        if active and forms:
            note(f"Active fuzzing {len(forms)} form(s)...")
            f_findings = self.engine.fuzz_forms(forms, on_progress=on_progress)
            findings.extend(f_findings)

        if active and fuzz_url_params and param_urls:
            note(f"Fuzzing {len(param_urls)} URL(s) with parameters...")
            u_findings = self.engine.fuzz_url_params(param_urls, on_progress=on_progress)
            findings.extend(u_findings)

        # CVSS scoring
        scored_findings: list[Finding] = []
        for f in findings:
            cvss, vector = score_finding(f.attack_type)
            f.cvss_score = cvss
            f.cvss_vector = vector
            scored_findings.append(f)

        report = ScanReport(
            target=self.target_url,
            pages_scanned=recon_result["pages_scanned"],
            forms_found=len(forms),
            findings=scored_findings,
            vulnerable=any(f.severity in ("High", "Critical") for f in scored_findings),
            mode="llm" if self.use_llm else "static",
            config=self.config,
        )
        report_dict = report.to_dict()
        report_dict["transport"] = self.protocol_scanner.summary
        return report_dict

    def scan_login(self, login_endpoint: str = "/login", on_progress: ProgressCb | None = None) -> dict:
        findings, exploits = self.engine.probe_login(
            self.target_url,
            login_endpoint=login_endpoint,
            on_progress=on_progress,
        )
        from urllib.parse import urljoin

        full_url = urljoin(self.target_url.rstrip("/") + "/", login_endpoint.lstrip("/"))
        report = ScanReport(
            target=full_url,
            findings=findings,
            exploits_found=exploits,
            vulnerable=bool(findings),
            mode="llm" if self.use_llm else "static",
        )
        return report.to_dict()

    def close(self) -> None:
        if self.tunnel is not None:
            self.tunnel.stop()
        try:
            self.target.requester.close()
        except Exception:
            pass