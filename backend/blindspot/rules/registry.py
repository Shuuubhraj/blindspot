"""Rule registry: collects every detection rule from the category modules.

Category modules (each created/maintained independently):
  manifest_rules  BS-M01..  manifest & Android configuration
  storage_rules   BS-S01..  insecure data storage & privacy
  network_rules   BS-N01..  network & transport security
  crypto_rules    BS-C01..  cryptography & secrets
  webview_rules   BS-W01..  WebView, input validation & injection
  auth_rules      BS-A01..  authentication, authorization & business logic
  platform_rules  BS-P01..  deep links, IPC, binary protection, supply chain

Each module exposes RULES: list[Rule].
"""

from __future__ import annotations

from . import (
    auth_rules,
    crypto_rules,
    manifest_rules,
    network_rules,
    platform_rules,
    storage_rules,
    webview_rules,
)
from .base import Rule

_MODULES = (
    manifest_rules,
    storage_rules,
    network_rules,
    crypto_rules,
    webview_rules,
    auth_rules,
    platform_rules,
)


def all_rules() -> list[Rule]:
    rules: list[Rule] = []
    for mod in _MODULES:
        rules.extend(mod.RULES)
    return rules


def get_registry() -> dict[str, Rule]:
    reg: dict[str, Rule] = {}
    for rule in all_rules():
        if rule.id in reg:
            raise ValueError(f"Duplicate rule id: {rule.id}")
        reg[rule.id] = rule
    return reg


def enabled_rules(config: dict | None = None) -> list[Rule]:
    """Rules enabled via config; config may contain disabled_rules: [ids]
    and enabled_rules: [ids] to force-enable."""
    config = config or {}
    disabled = set(config.get("disabled_rules", []))
    forced = set(config.get("enabled_rules", []))
    out = []
    for rule in all_rules():
        if rule.id in forced:
            out.append(rule)
        elif rule.id not in disabled and rule.enabled_by_default:
            out.append(rule)
    return out
