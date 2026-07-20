"""Mutation engine — generate payload variants through fuzzing and transformation."""

from __future__ import annotations

import random
import string
from collections.abc import Callable


class MutationEngine:
    """Generate payload mutations for fuzzing and evasion testing."""

    FUZZ_MODES = {
        "character_insertion": "Insert random characters at positions",
        "character_deletion": "Delete characters at random positions",
        "character_substitution": "Swap characters with similar-looking ones",
        "case_variation": "Random case changes",
        "boundary_testing": "Extreme lengths and empty strings",
        "encoding_variation": "URL, unicode, HTML entity encoding",
        "repeat_pattern": "Repeat characters or patterns",
        "null_injection": "Inject null bytes and control characters",
    }

    def __init__(self, mutation_count: int = 5):
        self.mutation_count = mutation_count
        self._mutators: list[Callable[[str], str]] = [
            self._insert_random_char,
            self._delete_random_char,
            self._substitute_similar,
            self._repeat_pattern,
            self._add_whitespace,
            self._swap_chars,
        ]

    def mutate(self, payload: str) -> list[str]:
        """Generate N mutated variants of the payload."""
        results: set[str] = set()
        results.add(payload)

        for _ in range(self.mutation_count * 3):
            if len(results) >= self.mutation_count + 1:
                break
            mutator = random.choice(self._mutators)
            try:
                mutated = mutator(payload)
                if mutated and mutated != payload:
                    results.add(mutated)
            except Exception:
                continue

        return list(results)

    def fuzz(self, payload: str) -> list[str]:
        """Generate aggressive fuzz variants (may break payload structure)."""
        results: list[str] = []
        for _ in range(self.mutation_count):
            mode = random.choice(list(self.FUZZ_MODES.keys()))
            try:
                if mode == "character_insertion":
                    pos = random.randint(0, len(payload))
                    char = random.choice(string.printable[:62])
                    results.append(payload[:pos] + char + payload[pos:])
                elif mode == "character_deletion":
                    if len(payload) > 1:
                        pos = random.randint(0, len(payload) - 1)
                        results.append(payload[:pos] + payload[pos + 1:])
                elif mode == "boundary_testing":
                    results.append("")
                    results.append("A" * 100)
                    results.append("A" * 1000)
                    results.append("\x00" * 10)
                elif mode == "null_injection":
                    results.append("\x00" + payload)
                    results.append(payload + "\x00")
                    results.append(payload.replace(" ", "\x00"))
            except Exception:
                continue

        return list(dict.fromkeys(results))

    def generate_variants(self, payload: str, count: int = 5) -> list[str]:
        """Generate context-aware payload variants."""
        variants: list[str] = [payload]

        url_encodings = [
            payload, payload.replace("'", "%27").replace('"', "%22"),
            payload.replace("<", "%3C").replace(">", "%3E"),
            payload.replace(" ", "+"),
        ]
        variants.extend(v for v in url_encodings if v not in variants)

        case_variants = [
            payload.upper(), payload.lower(), payload.title(),
            "".join(c.upper() if random.random() > 0.5 else c for c in payload),
        ]
        variants.extend(v for v in case_variants if v not in variants)

        quote_variants = [
            payload.replace("'", '"'),
            payload.replace('"', "'"),
        ]
        variants.extend(v for v in quote_variants if v not in variants)

        return variants[:max(count + 1, len(variants))]

    # ── Internal mutators ──────────────────────────────────────────

    def _insert_random_char(self, s: str) -> str:
        pos = random.randint(0, len(s))
        char = random.choice(string.printable[:62])
        return s[:pos] + char + s[pos:]

    def _delete_random_char(self, s: str) -> str:
        if len(s) <= 1:
            return s
        pos = random.randint(0, len(s) - 1)
        return s[:pos] + s[pos + 1:]

    def _substitute_similar(self, s: str) -> str:
        substitutes = {
            "a": ["@", "4"], "e": ["3"], "i": ["1", "!"], "o": ["0"],
            "s": ["5", "$"], "t": ["7"], "b": ["8"], "g": ["9"],
            "<": ["&lt;", "«"], ">": ["&gt;", "»"],
            "'": ["`", "´"], '"': ["``", "''"],
        }
        result = list(s)
        for i in range(len(result)):
            lower_c = result[i].lower()
            if lower_c in substitutes and random.random() < 0.3:
                result[i] = random.choice(substitutes[lower_c])
        return "".join(result)

    def _repeat_pattern(self, s: str) -> str:
        if len(s) < 2:
            return s + s
        segment_len = max(1, len(s) // random.randint(2, 4))
        segment = s[:segment_len]
        return segment * random.randint(2, 4)

    def _add_whitespace(self, s: str) -> str:
        whitespace = [" ", "\t", "\n", "\r", "\x0b", "\x0c"]
        if " " in s:
            return s.replace(" ", random.choice(whitespace), 1)
        return s + random.choice(whitespace)

    def _swap_chars(self, s: str) -> str:
        if len(s) < 2:
            return s
        pos = random.randint(0, len(s) - 2)
        chars = list(s)
        chars[pos], chars[pos + 1] = chars[pos + 1], chars[pos]
        return "".join(chars)
