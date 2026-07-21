"""Mobile application vulnerability scanning — Android/iOS API and config analysis."""

from __future__ import annotations

import json
import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from basilisk.models import Finding
from basilisk.scoring import score_finding

logger = logging.getLogger(__name__)

ANDROID_MANIFEST_CHECKS = [
    {"check": "android:allowBackup=\"true\"", "severity": "Medium", "desc": "App data can be backed up (adb backup)"},
    {"check": "android:debuggable=\"true\"", "severity": "High", "desc": "App is debuggable"},
    {"check": "android:exported=\"true\"", "severity": "Medium", "desc": "Component exported to other apps"},
    {"check": "android:usesCleartextTraffic=\"true\"", "severity": "High", "desc": "Cleartext HTTP traffic allowed"},
    {"check": "android:networkSecurityConfig", "severity": "Info", "desc": "Custom network security config"},
    {"check": "<uses-permission android:name=\"android.permission.INTERNET\"", "severity": "Info", "desc": "Internet permission"},
    {"check": "<uses-permission android:name=\"android.permission.CAMERA\"", "severity": "Medium", "desc": "Camera permission"},
    {"check": "<uses-permission android:name=\"android.permission.RECORD_AUDIO\"", "severity": "High", "desc": "Microphone permission"},
    {"check": "<uses-permission android:name=\"android.permission.ACCESS_FINE_LOCATION\"", "severity": "Medium", "desc": "Fine location permission"},
    {"check": "<uses-permission android:name=\"android.permission.READ_CONTACTS\"", "severity": "High", "desc": "Contacts read permission"},
    {"check": "<uses-permission android:name=\"android.permission.READ_SMS\"", "severity": "Critical", "desc": "SMS read permission"},
]

IOS_INFO_PLIST_CHECKS = [
    {"check": "NSAppTransportSecurity", "severity": "High", "desc": "ATS configuration found"},
    {"check": "NSAllowsArbitraryLoads", "severity": "Critical", "desc": "Arbitrary network loads allowed"},
    {"check": "NSPhotoLibraryUsageDescription", "severity": "Medium", "desc": "Photo library access"},
    {"check": "NSLocationAlwaysUsageDescription", "severity": "High", "desc": "Always-on location access"},
    {"check": "NSCameraUsageDescription", "severity": "Medium", "desc": "Camera access"},
    {"check": "NSMicrophoneUsageDescription", "severity": "Medium", "desc": "Microphone access"},
]

MOBILE_API_SECURITY_CHECKS = [
    {"check": r"api[_-]?key\s*=\s*['\"][^'\"]{16,}", "severity": "Critical", "desc": "Hardcoded API key"},
    {"check": r"secret\s*=\s*['\"][^'\"]{8,}", "severity": "Critical", "desc": "Hardcoded secret"},
    {"check": r"token\s*=\s*['\"][^'\"]{8,}", "severity": "High", "desc": "Hardcoded token"},
    {"check": r"password\s*=\s*['\"][^'\"]{4,}", "severity": "Critical", "desc": "Hardcoded password"},
    {"check": r"http://\w+\.\w+/api", "severity": "High", "desc": "HTTP (not HTTPS) API endpoint"},
]

APK_EXTRACT_PATTERNS = [
    "AndroidManifest.xml",
    "res/values/strings.xml",
    "classes.dex",
]


@dataclass
class MobileVuln:
    category: str
    severity: str
    description: str
    file: str = ""
    line: int = 0


@dataclass
class MobileScanResult:
    platform: str = ""
    vulnerabilities: list[MobileVuln] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class MobileScanner:
    """Scan mobile app binaries and source for security issues."""

    def scan_apk(self, apk_path: str | Path) -> MobileScanResult:
        result = MobileScanResult(platform="android")
        path = Path(apk_path)

        if not path.exists() or path.suffix not in (".apk", ".aab"):
            logger.warning("Not an APK/AAB file: %s", apk_path)
            return result

        try:
            with zipfile.ZipFile(path, "r") as zf:
                for name in zf.namelist():
                    if "AndroidManifest.xml" in name:
                        content = zf.read(name).decode("utf-8", errors="replace")
                        self._check_android_manifest(content, result)
                    elif name.endswith(".xml") and "res" in name:
                        content = zf.read(name).decode("utf-8", errors="replace")
                        self._check_xml_secrets(content, name, result)
                    elif name.endswith(".js") or name.endswith(".html"):
                        content = zf.read(name).decode("utf-8", errors="replace")
                        self._check_mobile_api_secrets(content, name, result)
        except (zipfile.BadZipFile, Exception) as e:
            logger.debug("APK analysis failed: %s", e)

        self._findings_from_vulns(result)
        return result

    def scan_ios(self, ipa_path: str | Path) -> MobileScanResult:
        result = MobileScanResult(platform="ios")
        path = Path(ipa_path)

        if not path.exists() or path.suffix not in (".ipa", ".app"):
            logger.warning("Not an IPA file: %s", ipa_path)
            return result

        try:
            with zipfile.ZipFile(path, "r") as zf:
                for name in zf.namelist():
                    if "Info.plist" in name:
                        content = zf.read(name).decode("utf-8", errors="replace")
                        self._check_ios_plist(content, result)
                    elif name.endswith(".js") or name.endswith(".swift") or name.endswith(".m"):
                        content = zf.read(name).decode("utf-8", errors="replace")
                        self._check_mobile_api_secrets(content, name, result)
        except (zipfile.BadZipFile, Exception) as e:
            logger.debug("IPA analysis failed: %s", e)

        self._findings_from_vulns(result)
        return result

    def scan_source(self, source_dir: str | Path) -> MobileScanResult:
        result = MobileScanResult(platform="source")
        path = Path(source_dir)

        if not path.is_dir():
            return result

        for pattern in ["**/*.swift", "**/*.kt", "**/*.java", "**/*.js", "**/*.ts", "**/*.gradle", "**/*.xml"]:
            for f in path.glob(pattern):
                if "node_modules" in str(f) or ".git" in str(f):
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    name = f.name
                    if name == "AndroidManifest.xml":
                        self._check_android_manifest(content, result)
                    elif name == "Info.plist" or name == "info.plist":
                        self._check_ios_plist(content, result)
                    else:
                        self._check_mobile_api_secrets(content, str(f), result)
                except Exception:
                    continue

        self._findings_from_vulns(result)
        return result

    def _check_android_manifest(self, content: str, result: MobileScanResult) -> None:
        for check in ANDROID_MANIFEST_CHECKS:
            if check["check"] in content:
                result.vulnerabilities.append(MobileVuln(
                    category="Android Manifest",
                    severity=check["severity"],
                    description=check["desc"],
                    file="AndroidManifest.xml",
                ))

    def _check_ios_plist(self, content: str, result: MobileScanResult) -> None:
        for check in IOS_INFO_PLIST_CHECKS:
            if check["check"] in content:
                result.vulnerabilities.append(MobileVuln(
                    category="iOS Info.plist",
                    severity=check["severity"],
                    description=check["desc"],
                    file="Info.plist",
                ))

    def _check_xml_secrets(self, content: str, filename: str, result: MobileScanResult) -> None:
        for check in MOBILE_API_SECURITY_CHECKS[:3]:
            if re.search(check["check"], content, re.I):
                result.vulnerabilities.append(MobileVuln(
                    category="XML Secret",
                    severity=check["severity"],
                    description=check["desc"],
                    file=filename,
                ))

    def _check_mobile_api_secrets(self, content: str, filename: str, result: MobileScanResult) -> None:
        for check in MOBILE_API_SECURITY_CHECKS:
            for match in re.finditer(check["check"], content, re.I):
                result.vulnerabilities.append(MobileVuln(
                    category="Mobile Code Secret",
                    severity=check["severity"],
                    description=f"{check['desc']}: {match.group()[:40]}",
                    file=filename,
                ))

    def _findings_from_vulns(self, result: MobileScanResult) -> None:
        for v in result.vulnerabilities:
            cvss, vector = score_finding("mobile_api")
            result.findings.append(
                Finding(
                    vulnerability=f"Mobile Security: {v.description}",
                    severity=v.severity,
                    description=f"[{v.category}] {v.description} in {v.file}",
                    target=v.file,
                    attack_type="mobile_api",
                    cvss_score=cvss,
                    cvss_vector=vector,
                    remediation=f"Fix mobile security issue in {v.file}: {v.description}",
                )
            )


def scan_mobile(path: str | Path) -> MobileScanResult:
    p = Path(path)
    scanner = MobileScanner()
    if p.suffix in (".apk", ".aab"):
        return scanner.scan_apk(p)
    elif p.suffix in (".ipa", ".app"):
        return scanner.scan_ios(p)
    elif p.is_dir():
        return scanner.scan_source(p)
    return MobileScanResult()
