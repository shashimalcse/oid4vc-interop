"""Load a target profile directory.

Substitution happens in two passes over the raw YAML:
  1. `${VAR}` / `${VAR:-default}` from the environment (plus the target's env_files), at load;
  2. `${setup.path.to.value}` from the setup hook's JSON output, after the hook ran.
`{{ session }}` and `{{ run_id }}` in HTTP requests are rendered later, at call time.
"""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .schema import ConfigError, TargetProfile

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_SETUP_REF = re.compile(r"\$\{setup\.([A-Za-z0-9_.-]+)\}")
_SECRET_KEYS = {"password", "token", "secret", "client_secret"}


def _walk(value: Any, fn) -> Any:
    if isinstance(value, dict):
        return {k: _walk(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(v, fn) for v in value]
    return fn(value) if isinstance(value, str) else value


def substitute_env(value: Any, env: dict[str, str], missing: set[str]) -> Any:
    def one(s: str) -> str:
        def repl(m: re.Match[str]) -> str:
            name, default = m.group(1), m.group(2)
            if name in env:
                return env[name]
            if default is not None:
                return default
            missing.add(name)
            return ""

        return _ENV_REF.sub(repl, s)

    return _walk(value, one)


def lookup(data: Any, dotted: str) -> Any:
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        elif isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise KeyError(dotted)
    return cur


def substitute_setup(value: Any, setup: dict[str, Any], missing: set[str]) -> Any:
    def one(s: str) -> Any:
        whole = _SETUP_REF.fullmatch(s)
        if whole:  # a lone reference keeps the JSON type (number, object, list)
            try:
                return lookup(setup, whole.group(1))
            except KeyError:
                missing.add(whole.group(1))
                return s

        def repl(m: re.Match[str]) -> str:
            try:
                return str(lookup(setup, m.group(1)))
            except KeyError:
                missing.add(m.group(1))
                return m.group(0)

        return _SETUP_REF.sub(repl, s)

    return _walk(value, one)


def has_setup_refs(value: Any) -> bool:
    found = []
    _walk(value, lambda s: found.append(1) if _SETUP_REF.search(s) else s)
    return bool(found)


def read_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip().removeprefix("export ").strip()] = v.strip().strip("'\"")
    return out


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("***" if k in _SECRET_KEYS and v else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class LoadedTarget:
    """The raw YAML after env substitution, plus its validated model.

    The model is rebuilt by `resolve_setup` once the setup hook has produced values.
    """

    def __init__(self, directory: Path, raw: dict[str, Any], env: dict[str, str] | None = None):
        self.directory = directory
        self.raw = raw
        self.env = env or {}  # process environment plus env_files: what hooks and commands see
        self.model = self._validate(raw)

    def _validate(self, raw: dict[str, Any]) -> TargetProfile:
        try:
            model = TargetProfile.model_validate(raw)
        except ValidationError as e:
            raise ConfigError(f"{self.directory / 'target.yaml'}: {e}") from e
        model.directory = self.directory
        return model

    def resolve_setup(self, setup: dict[str, Any]) -> TargetProfile:
        missing: set[str] = set()
        resolved = substitute_setup(copy.deepcopy(self.raw), setup, missing)
        if missing:
            raise ConfigError(f"setup hook output lacks: {', '.join('setup.' + m for m in sorted(missing))}")
        self.model = self._validate(resolved)
        return self.model

    @property
    def needs_setup_values(self) -> bool:
        return has_setup_refs(self.raw)


def load_target(directory: str | Path, env: dict[str, str] | None = None) -> LoadedTarget:
    directory = Path(directory).resolve()
    if directory.is_file():
        directory = directory.parent
    path = directory / "target.yaml"
    try:
        raw = yaml.safe_load(path.read_text())
    except FileNotFoundError as e:
        raise ConfigError(f"no target.yaml in {directory}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"{path}: invalid YAML: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")

    environment = dict(os.environ) if env is None else dict(env)
    for f in raw.get("env_files") or []:
        p = directory / f
        if p.exists():
            # The process environment wins over the file, so CI can override anything.
            environment = {**read_env_file(p), **environment}

    missing: set[str] = set()
    resolved = substitute_env(raw, environment, missing)
    if missing:
        raise ConfigError(f"{path}: environment variables not set: {', '.join(sorted(missing))}")
    return LoadedTarget(directory, resolved, environment)
