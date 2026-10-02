"""Controller-owned execution choices, structurally separate from authorization.

Compatibility describes the installed client/adapter contract, not the quality
or authenticated identity of whichever upstream model the gateway serves.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from types import MappingProxyType


class ModelProfileError(ValueError):
    """Only fixed safe codes; never echo supplied configuration."""


@dataclass(frozen=True, slots=True)
class ModelProfile:
    profile_id: str
    adapter_id: str
    model_id: str | None
    roles: frozenset[str]
    supports_tools: bool
    supports_streaming: bool
    supports_structured_result: bool
    supports_dynamic_tool_schema: bool
    supports_result_envelope: bool
    supports_long_agent_session: bool
    context_class: str
    cost_class: str
    availability_class: str
    qualification_status: str = "CONFIGURED"


MODEL_ROLES = frozenset(("planner", "coder", "fixer", "reviewer"))
ROLES = MODEL_ROLES | {"researcher"}
REGISTRY = MappingProxyType({
    "claude-free-default": ModelProfile(
        "claude-free-default", "claude-code-freellmapi", None, MODEL_ROLES,
        True, True, True, True, True, True, "UNKNOWN", "CONFIGURED", "CONFIGURED"),
    # The installed gateway accepts auto. Opt-in only; no upstream identity promise.
    "claude-free-auto": ModelProfile(
        "claude-free-auto", "claude-code-freellmapi", "auto", MODEL_ROLES,
        True, True, True, True, True, True, "UNKNOWN", "CONFIGURED", "CONFIGURED"),
    # Local enabled Groq catalog entry; tools/context configured, live qualification pending.
    "claude-free-gpt-oss-120b": ModelProfile(
        "claude-free-gpt-oss-120b", "claude-code-freellmapi", "openai/gpt-oss-120b",
        frozenset(("coder", "fixer")), True, True, False, True, True, True,
        "128K_CONFIGURED", "CONFIGURED", "CONFIGURED"),
    "research-tools": ModelProfile(
        "research-tools", "bounded-research-tools", None, frozenset(("researcher",)),
        False, False, False, False, False, False, "NOT_APPLICABLE", "CONFIGURED", "CONFIGURED"),
})
DEFAULTS = MappingProxyType({role: "claude-free-default" if role in MODEL_ROLES else "research-tools"
                           for role in ROLES})
REQUIREMENTS = MappingProxyType({
    "planner": ("supports_structured_result", "supports_result_envelope"),
    "reviewer": ("supports_structured_result", "supports_result_envelope"),
    "coder": ("supports_tools", "supports_streaming", "supports_dynamic_tool_schema",
              "supports_result_envelope", "supports_long_agent_session"),
    "fixer": ("supports_tools", "supports_streaming", "supports_dynamic_tool_schema",
              "supports_result_envelope", "supports_long_agent_session"),
    "researcher": (),
})
_selection = ContextVar("controller_model_selection", default=None)


def validate_compatibility(profile, role):
    if role not in ROLES:
        raise ModelProfileError("MODEL_ROLE_INVALID")
    if not isinstance(profile, ModelProfile) or role not in profile.roles:
        raise ModelProfileError("MODEL_PROFILE_INCOMPATIBLE")
    expected = "bounded-research-tools" if role == "researcher" else "claude-code-freellmapi"
    if profile.adapter_id != expected or any(getattr(profile, key) is not True for key in REQUIREMENTS[role]):
        raise ModelProfileError("MODEL_PROFILE_INCOMPATIBLE")
    return profile


def resolve_profile(role, profile_id="auto"):
    if not isinstance(role, str) or role not in ROLES:
        raise ModelProfileError("MODEL_ROLE_INVALID")
    if not isinstance(profile_id, str) or not 1 <= len(profile_id) <= 48:
        raise ModelProfileError("MODEL_PROFILE_INVALID")
    if profile_id == "auto":
        profile_id = DEFAULTS[role]
    profile = REGISTRY.get(profile_id)
    if profile is None:
        raise ModelProfileError("MODEL_PROFILE_UNKNOWN")
    return validate_compatibility(profile, role)


def configured_selection(overrides=None):
    """Trusted API/CLI configuration only; never reads task or model state."""
    if overrides is not None and (not isinstance(overrides, (dict, MappingProxyType)) or len(overrides) > len(ROLES)):
        raise ModelProfileError("MODEL_SELECTION_INVALID")
    from foundation import current_config
    result = dict(DEFAULTS)
    result.update(dict(current_config().model_profiles))
    for role, profile_id in (overrides or {}).items():
        result[role] = resolve_profile(role, profile_id).profile_id
    for role, profile_id in result.items():
        resolve_profile(role, profile_id)
    return MappingProxyType(result)


@contextmanager
def profile_scope(overrides=None):
    """Isolate graph invocations; reset on every exit, including exceptions."""
    token = _selection.set(configured_selection(overrides))
    try:
        yield
    finally:
        _selection.reset(token)


def selected_profile(role):
    selection = _selection.get()
    if selection is None:
        from foundation import current_config
        selection = dict(current_config().model_profiles)
    return resolve_profile(role, selection.get(role, "auto"))


def requested_identity(role):
    profile = selected_profile(role)
    return {"model_profile_id": profile.profile_id, "adapter_id": profile.adapter_id,
            "requested_model_id": profile.model_id or ("NOT_APPLICABLE" if role == "researcher" else "CLIENT_DEFAULT"),
            "compatibility": "VALIDATED", "served_model_id": "UNAVAILABLE",
            "qualification_status": profile.qualification_status}


def safe_model_selection(value):
    """Only exact registry-derived identities survive projection; no env/payloads."""
    if not isinstance(value, dict) or not isinstance(value.get("model_profile_id"), str):
        return {}
    profile = REGISTRY.get(value["model_profile_id"])
    if profile is None:
        return {}
    expected = {"model_profile_id": profile.profile_id, "adapter_id": profile.adapter_id,
                "requested_model_id": profile.model_id or ("NOT_APPLICABLE" if profile.roles == frozenset(("researcher",)) else "CLIENT_DEFAULT"),
                "compatibility": "VALIDATED", "served_model_id": "UNAVAILABLE",
                "qualification_status": profile.qualification_status}
    # Preserve projection of older evidence; only the controller registry supplies this label.
    return expected if all(value.get(key, item if key == "qualification_status" else None) == item
                           for key, item in expected.items()) else {}


def model_command(role, tool_flags, prompt, *, schema=None):
    """Only model selection varies; supplied sealed tool flags are copied intact."""
    profile = selected_profile(role)
    if role not in MODEL_ROLES:
        raise ModelProfileError("MODEL_ROLE_INVALID")
    from foundation import current_config
    cmd = [current_config().launcher]
    if profile.model_id is not None:
        cmd += ["--model", profile.model_id]
    if role in ("coder", "fixer"):
        if schema is not None:
            raise ModelProfileError("MODEL_COMMAND_INVALID")
        cmd += ["--output-format", "stream-json", "--verbose", "--no-session-persistence",
                *tool_flags, "--permission-mode", "dontAsk", "--permission-prompts", "none"]
    else:
        if not isinstance(schema, str) or not schema:
            raise ModelProfileError("MODEL_COMMAND_INVALID")
        cmd += [*tool_flags, "--permission-mode", "dontAsk", "--permission-prompts", "none",
                "--output-format", "json", "--json-schema", schema]
    return [*cmd, "-p", prompt]


def command_identity(cmd, role):
    """Check requested identity at execution, independently of model output."""
    identity = requested_identity(role)
    expected = selected_profile(role).model_id
    # All supported model commands end with -p, prompt. Prompt is never an option.
    options = cmd[:-2]
    if len(cmd) < 3 or cmd[-2] != "-p" or any(value.startswith("--model=") for value in options):
        raise ModelProfileError("MODEL_COMMAND_INVALID")
    flags = [i for i, value in enumerate(options) if value == "--model"]
    if ((expected is None and flags) or expected is not None and
            (len(flags) != 1 or flags[0] + 1 >= len(options) or options[flags[0] + 1] != expected)):
        raise ModelProfileError("MODEL_COMMAND_IDENTITY_MISMATCH")
    return identity
