"""Ephemeral context mappings. Session secrets are resolved only for execution."""
import json
import os
import re
from dataclasses import replace

ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class RuntimeContext:
    def __init__(self, mappings=None, sessions=None):
        self.mappings = mappings or {}
        self.sessions = sessions or {}
        if not isinstance(self.mappings, dict) or not isinstance(self.sessions, dict):
            raise ValueError("Runtime mappings and sessions must be objects")
        for name, session in self.sessions.items():
            if not isinstance(session, dict) or set(session) - {"role", "cookie_env"}:
                raise ValueError("Sessions accept role and cookie_env references only")
            if not isinstance(session.get("role"), str) or not ENV_NAME.fullmatch(session.get("cookie_env", "")):
                raise ValueError("Session requires role and valid cookie_env name")
        for validators in self.mappings.values():
            if not isinstance(validators, dict) or any(not isinstance(v, dict) for v in validators.values()):
                raise ValueError("Mappings must be parent-ID -> validator-ID -> context objects")
            self._reject_secrets(validators)

    @classmethod
    def _reject_secrets(cls, value):
        if isinstance(value, dict):
            for key, item in value.items():
                if re.search(r"password|authorization|^cookie$|^secret$|^token$|sesskey", key, re.I):
                    raise ValueError("Literal credentials are prohibited in runtime context")
                cls._reject_secrets(item)
        elif isinstance(value, list):
            for item in value:
                cls._reject_secrets(item)

    @classmethod
    def from_env(cls, name):
        if not ENV_NAME.fullmatch(name):
            raise ValueError("Invalid runtime context environment variable name")
        if name not in os.environ:
            raise ValueError("Runtime context environment variable is unavailable")
        payload = json.loads(os.environ[name])
        if not isinstance(payload, dict) or set(payload) - {"mappings", "sessions"}:
            raise ValueError("Runtime context accepts mappings and sessions only")
        return cls(**payload)

    def parent_for(self, parent, validator):
        mapped = self.mappings.get(parent.evidence_id, self.mappings.get(parent.finding_id, {})).get(validator, {})
        evidence = dict(parent.evidence) if isinstance(parent.evidence, dict) else {}
        original = evidence.get("active_context")
        context = dict(original) if isinstance(original, dict) else {}
        context.update(mapped)
        if mapped:
            context["validator"] = validator
        evidence["active_context"] = context
        return replace(parent, evidence=evidence)

    def session_available(self, reference):
        return reference in self.sessions and bool(os.environ.get(self.sessions[reference]["cookie_env"]))

    def cookie(self, reference):
        if not self.session_available(reference):
            raise ValueError("Required ephemeral session is unavailable")
        value = os.environ[self.sessions[reference]["cookie_env"]]
        if '\r' in value or '\n' in value or len(value) > 8192 or '=' not in value:
            raise ValueError("Invalid ephemeral Cookie header")
        return value
