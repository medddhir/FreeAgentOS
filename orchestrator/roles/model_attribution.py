"""Identity provenance boundary, independent of selection and authorization.

The installed Anthropic gateway exposes dispatch headers, but Claude Code does
not forward them through our NDJSON interface. No request-bound controller
channel exists today. Never ingest worker/model claims as gateway evidence.
"""
from roles.model_profiles import REGISTRY, requested_identity

# Vocabulary for evidence strength, not assertions that these channels exist.
EVIDENCE_LEVELS = ("REQUESTED_CONFIG", "ROUTER_DISPATCH", "UPSTREAM_REPORTED", "UNAVAILABLE")


def _unavailable(profile):
    return {"requested_profile_id": profile.profile_id, "adapter_id": profile.adapter_id,
            "requested_model_id": profile.model_id or (
                "NOT_APPLICABLE" if profile.roles == frozenset(("researcher",)) else "CLIENT_DEFAULT"),
            "requested_evidence": "REQUESTED_CONFIG",
            "routed_provider_id": "UNAVAILABLE", "routed_model_id": "UNAVAILABLE",
            "routed_evidence": "UNAVAILABLE", "served_model_id": "UNAVAILABLE",
            "served_evidence": "UNAVAILABLE",
            "attribution_status": "GATEWAY_SESSION_BINDING_UNAVAILABLE"}


def attribution_for(role):
    """Derive requested identity from controller scope; do not read transport."""
    identity = requested_identity(role)
    return _unavailable(REGISTRY[identity["model_profile_id"]])


def safe_attribution(value):
    """Project only implemented provenance. No echoed/claimed route is trusted.

    Future request-bound gateway instrumentation needs its own authenticated
    ingestion boundary; syntax or an evidence label cannot grant provenance.
    """
    if not isinstance(value, dict) or not isinstance(value.get("requested_profile_id"), str):
        return {}
    profile = REGISTRY.get(value["requested_profile_id"])
    if profile is None:
        return {}
    expected = _unavailable(profile)
    return expected if all(value.get(key) == item for key, item in expected.items()) else {}
