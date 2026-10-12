"""Profile registry: YAML profile id -> implementation."""

from __future__ import annotations

from importlib import import_module

from .base import Profile

_REGISTRY = {
    "vci-base": "vcit.profiles.vci:VciBaseProfile",
    "vci-haip": "vcit.profiles.vci:VciHaipProfile",
    "vp-base": "vcit.profiles.vp:VpBaseProfile",
    "vp-haip": "vcit.profiles.vp:VpHaipProfile",
    "wallet-interop": "vcit.profiles.wallet_interop:WalletInteropProfile",
}


def profile_class(profile_id: str) -> type[Profile]:
    module, _, name = _REGISTRY[profile_id].partition(":")
    return getattr(import_module(module), name)
