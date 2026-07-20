"""Adaptive payload evolution — payloads mutate based on target responses."""

from __future__ import annotations

import hashlib
import random
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from basilisk.encoding import EncodingEngine


@dataclass
class PayloadCandidate:
    """A payload with fitness metadata for the adaptive engine."""
    payload: str
    fitness: float = 0.0
    generation: int = 0
    parent_hash: str = ""
    mutations_applied: list[str] = field(default_factory=list)

    @property
    def hash(self) -> str:
        return hashlib.md5(self.payload.encode()).hexdigest()[:8]


class AdaptiveEngine:
    """Evolve payloads based on target feedback using genetic mutation strategies."""

    MUTATION_STRATEGIES = [
        "case_swap",
        "url_encode",
        "double_encode",
        "comment_inject",
        "whitespace_vary",
        "char_substitute",
        "concat_split",
        "unicode_escape",
        "null_byte_inject",
        "nested_encode",
    ]

    def __init__(
        self,
        population_size: int = 20,
        max_generations: int = 5,
        mutation_rate: float = 0.3,
        elite_ratio: float = 0.2,
    ):
        self.population_size = population_size
        self.max_generations = max_generations
        self.mutation_rate = mutation_rate
        self.elite_ratio = elite_ratio
        self.encoder = EncodingEngine()

    def evolve(
        self,
        seed_payloads: list[str],
        fitness_fn: Callable[[str], float],
        on_generation: Callable[[int, list[PayloadCandidate]], None] | None = None,
    ) -> list[PayloadCandidate]:
        """
        Evolve payloads through mutation + selection.

        fitness_fn(payload) -> float:
            Returns a score [0..1] based on the target response.
            Higher = more interesting (closer to vulnerability).
        """
        # Seed initial population
        population = [
            PayloadCandidate(payload=p, generation=0)
            for p in seed_payloads[:self.population_size]
        ]

        # Fill remaining slots with mutations of seeds
        while len(population) < self.population_size and seed_payloads:
            base = random.choice(seed_payloads)
            mutated = self._mutate(base)
            if mutated != base:
                population.append(
                    PayloadCandidate(payload=mutated, generation=0, mutations_applied=["initial_mutate"])
                )

        best_ever: list[PayloadCandidate] = []

        for gen in range(self.max_generations):
            # Evaluate fitness
            for candidate in population:
                if candidate.fitness == 0.0:
                    candidate.fitness = fitness_fn(candidate.payload)

            # Sort by fitness (descending)
            population.sort(key=lambda c: c.fitness, reverse=True)

            # Track best
            for c in population[:3]:
                if c.fitness > 0 and c.payload not in {b.payload for b in best_ever}:
                    best_ever.append(c)

            if on_generation:
                on_generation(gen, population[:5])

            # Early exit if we found strong hits
            if any(c.fitness >= 0.9 for c in population):
                break

            # Selection: keep elite, breed the rest
            elite_count = max(2, int(len(population) * self.elite_ratio))
            elites = population[:elite_count]

            new_population = list(elites)
            while len(new_population) < self.population_size:
                parent = random.choice(elites)
                if random.random() < self.mutation_rate:
                    child_payload = self._mutate(parent.payload)
                    strategy = random.choice(self.MUTATION_STRATEGIES)
                    child = PayloadCandidate(
                        payload=child_payload,
                        generation=gen + 1,
                        parent_hash=parent.hash,
                        mutations_applied=[strategy],
                    )
                else:
                    # Crossover between two parents
                    other = random.choice(elites)
                    child_payload = self._crossover(parent.payload, other.payload)
                    child = PayloadCandidate(
                        payload=child_payload,
                        generation=gen + 1,
                        parent_hash=parent.hash,
                        mutations_applied=["crossover"],
                    )
                if child.payload not in {c.payload for c in new_population}:
                    new_population.append(child)

            population = new_population

        # Final evaluation
        for candidate in population:
            if candidate.fitness == 0.0:
                candidate.fitness = fitness_fn(candidate.payload)

        population.sort(key=lambda c: c.fitness, reverse=True)
        return (best_ever + population)[:self.population_size]

    def _mutate(self, payload: str) -> str:
        strategy = random.choice(self.MUTATION_STRATEGIES)
        mutators = {
            "case_swap": self._case_swap,
            "url_encode": self._url_encode_random,
            "double_encode": self._double_encode_random,
            "comment_inject": self._comment_inject,
            "whitespace_vary": self._whitespace_vary,
            "char_substitute": self._char_substitute,
            "concat_split": self._concat_split,
            "unicode_escape": self._unicode_escape,
            "null_byte_inject": self._null_byte_inject,
            "nested_encode": self._nested_encode,
        }
        fn = mutators.get(strategy, self._case_swap)
        result = fn(payload)
        return result if result else payload

    def _crossover(self, a: str, b: str) -> str:
        if len(a) < 2 or len(b) < 2:
            return a
        point = random.randint(1, min(len(a), len(b)) - 1)
        return a[:point] + b[point:]

    # ── Mutation operators ─────────────────────────────────────────────

    def _case_swap(self, payload: str) -> str:
        chars = list(payload)
        for i in range(len(chars)):
            if chars[i].isalpha() and random.random() < 0.3:
                chars[i] = chars[i].swapcase()
        return "".join(chars)

    def _url_encode_random(self, payload: str) -> str:
        chars = list(payload)
        for i in range(len(chars)):
            if not chars[i].isalnum() and random.random() < 0.4:
                chars[i] = f"%{ord(chars[i]):02X}"
        return "".join(chars)

    def _double_encode_random(self, payload: str) -> str:
        chars = list(payload)
        for i in range(len(chars)):
            if not chars[i].isalnum() and random.random() < 0.25:
                chars[i] = f"%25{ord(chars[i]):02X}"
        return "".join(chars)

    def _comment_inject(self, payload: str) -> str:
        comment_styles = ["/**/", "/*!*/", "/*x*/", "-- -", "#"]
        if " " in payload:
            comment = random.choice(comment_styles)
            parts = payload.split(" ", 1)
            return f"{parts[0]}{comment}{parts[1]}"
        return payload

    def _whitespace_vary(self, payload: str) -> str:
        ws_alternatives = ["\t", "\n", "\r", "\x0b", "\x0c", "%09", "%0a", "%0d"]
        if " " in payload:
            alt = random.choice(ws_alternatives)
            idx = payload.index(" ")
            return payload[:idx] + alt + payload[idx + 1:]
        return payload

    def _char_substitute(self, payload: str) -> str:
        subs = {
            "'": ["\u2019", "\uFF07", "%27", "\\x27"],
            '"': ["\u201D", "\uFF02", "%22", "\\x22"],
            "<": ["\uFF1C", "%3C", "\\x3C", "&lt;"],
            ">": ["\uFF1E", "%3E", "\\x3E", "&gt;"],
            "/": ["\uFF0F", "%2F", "\\x2F"],
        }
        chars = list(payload)
        for i in range(len(chars)):
            if chars[i] in subs and random.random() < 0.3:
                chars[i] = random.choice(subs[chars[i]])
        return "".join(chars)

    def _concat_split(self, payload: str) -> str:
        if "SELECT" in payload.upper():
            return re.sub(r"SELECT", "SE" + "/**/LECT", payload, flags=re.I, count=1)
        if "UNION" in payload.upper():
            return re.sub(r"UNION", "UN" + "/**/ION", payload, flags=re.I, count=1)
        if "<script" in payload.lower():
            return payload.replace("<script", "<scr\x00ipt", 1)
        return payload

    def _unicode_escape(self, payload: str) -> str:
        chars = list(payload)
        for i in range(len(chars)):
            if chars[i].isalpha() and random.random() < 0.2:
                chars[i] = f"\\u{ord(chars[i]):04X}"
        return "".join(chars)

    def _null_byte_inject(self, payload: str) -> str:
        positions = [0, len(payload) // 2, len(payload)]
        pos = random.choice(positions)
        null = random.choice(["%00", "\x00", "\\0"])
        return payload[:pos] + null + payload[pos:]

    def _nested_encode(self, payload: str) -> str:
        encoded = self.encoder.url_encode(payload)
        if random.random() < 0.5:
            encoded = self.encoder.html_entity_encode(encoded)
        return encoded


def calculate_fitness(response: dict | None, payload: str, kind: str) -> float:
    """
    Score a target response for adaptive selection.

    Returns 0.0 (no signal) to 1.0 (confirmed vulnerability).
    """
    if not response:
        return 0.0

    score = 0.0
    status = response.get("status_code", 0)
    body = response.get("body", "")
    elapsed = response.get("elapsed_time", 0)
    lower_body = body.lower()

    # HTTP 500 — strong signal
    if status == 500:
        score += 0.6

    # Error signatures
    error_sigs = [
        "sql syntax", "mysql_fetch", "unclosed quotation",
        "sqlite3.operationalerror", "warning: mysql", "odbc driver",
    ]
    for sig in error_sigs:
        if sig in lower_body:
            score += 0.3
            break

    # Payload reflection (XSS signal)
    if kind in ("xss", "dom_xss") and payload in body:
        score += 0.7

    # Timing anomaly (blind injection signal)
    if elapsed >= 5.0:
        score += 0.5
    elif elapsed >= 3.0:
        score += 0.2

    # Status anomalies
    if status in (301, 302, 307, 308):
        score += 0.15
    if status == 403:
        score += 0.1  # WAF might be blocking — payload is interesting

    # Command execution signatures
    cmdi_sigs = ["uid=", "root:", "www-data", "linux version"]
    if kind == "cmdi" and any(s in lower_body for s in cmdi_sigs):
        score += 0.8

    return min(score, 1.0)
