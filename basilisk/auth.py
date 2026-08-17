"""
Basilisk auth helpers — local LLM configuration only.

Basilisk is a fully standalone local CLI scanner.
There is no Basilisk cloud service, backend, or dashboard.
Network communication only happens when:
  - scanning the target specified by the user
  - calling an LLM provider explicitly configured by the user (BASILISK_LLM_API_KEY)
  - connecting to a local Ollama instance
"""
# This module is kept as a stub for backwards compatibility.
# All SaaS/device-code authentication has been removed.
