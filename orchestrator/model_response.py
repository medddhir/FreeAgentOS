"""Transport-shape extraction for model responses. Data only; no authority.

Pure standard-library module, independent of launchers, brokers, privileged
code and website validation. ``extract_model_response`` recovers the single
structured proposal object from a model transport envelope and re-encodes it
canonically. It never inspects, repairs or injects the website proposal
binding (run, phase, contract, base_snapshot, profile, version) or its files
array: those pass through untouched for ``website.validate_proposal``, which
stays responsible for binding equality, file paths, content policy, schema and
per-file/project limits.

Exactly three transport forms are supported: a ``structured_output`` object, a
``result`` string holding one strict JSON object, or a direct object that
contains none of the envelope keys. A null ``structured_output``/``result`` is
treated as absent; two non-null candidates are ambiguous and rejected even
when the secondary candidate is malformed; ``is_error``, ``error`` and ``type``
are checked for value and type before any candidate is selected.

The transport ``type`` field, when present, is matched exactly: ``"result"`` is
the only supported value, ``"error"`` is a model error, any other string
(including case or whitespace variants) is an unsupported type, and a
non-string is a field type error.

Rejection is deliberately conservative. Duplicate object keys anywhere,
non-finite or over-long numbers, invalid UTF-8, a byte-order mark, trailing or
multiple JSON values, mismatched, unbalanced or over-nested structure,
wrong-typed envelope fields and ambiguous candidates all fail with a fixed
code. The guarantee is a fixed message equal to that code plus a suppressed
displayed exception chain (``raise ... from None``); traceback frames can still
reference the input and the suppressed parser exception, so no memory-erasure
claim is made. Finite non-integer numbers are parsed and preserved so that the
website validator can reject them; this module does not enforce the proposal
schema.

Compatibility limits, not established by this source: the structural bounds
admit exactly the website proposal plus one outer envelope (outer depth 4 and
seven containers; JSON inside a ``result`` string is bounded at the proposal
itself, depth 3 and six containers). A client envelope carrying additional
object- or array-valued metadata fields is therefore rejected, as is any
``type`` value other than the exact string ``"result"``. Numbers that overflow
to infinity and integer tokens longer than twenty characters are rejected
here. Nothing in this module establishes Claude CLI compatibility,
kernel containment or live model access.
"""
import json
import math

MAX_RESPONSE_BYTES = 64 * 1024
MAX_OUTER_DEPTH = 4
MAX_OUTER_CONTAINERS = 7
MAX_RESULT_DEPTH = 3
MAX_RESULT_CONTAINERS = 6
MAX_NUMBER_CHARS = 20
MAX_FLOAT_CHARS = 32
ENVELOPE_KEYS = frozenset(("structured_output", "result", "error", "is_error", "type"))


class ResponseExtractionError(ValueError):
    """Fixed transport-shape rejection.

    The message is exactly the fixed code and ``raise ... from None`` sets
    ``__suppress_context__`` so the displayed chain is suppressed. Traceback
    frames can still reference the input and the suppressed parser exception;
    nothing here erases them.
    """

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class _Structure(Exception):
    pass


class _Json(Exception):
    pass


def _reject(code):
    raise ResponseExtractionError(code) from None


def _scan(text, max_depth, max_containers):
    """Escape-aware scan with a bounded bracket stack; runs before ``json.loads``."""
    stack = []
    containers = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            containers += 1
            if containers > max_containers or len(stack) >= max_depth:
                raise _Structure()
            stack.append(char)
        elif char in "]}":
            if not stack or stack.pop() != ("{" if char == "}" else "["):
                raise _Structure()
    if quoted or stack:
        raise _Structure()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _Json()
        result[key] = value
    return result


def _integer(token):
    if len(token) > MAX_NUMBER_CHARS:
        raise _Json()
    return int(token)


def _float(token):
    if len(token) > MAX_FLOAT_CHARS:
        raise _Json()
    value = float(token)
    if not math.isfinite(value):
        raise _Json()
    return value


def _constant(token):
    raise _Json()


def _load(text, max_depth, max_containers):
    try:
        _scan(text, max_depth, max_containers)
    except _Structure:
        _reject("RESPONSE_STRUCTURE")
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                          parse_float=_float, parse_constant=_constant)
    except (json.JSONDecodeError, _Json, ValueError, TypeError, RecursionError):
        _reject("RESPONSE_JSON")


def _check_fields(value):
    if "is_error" in value:
        flag = value["is_error"]
        if type(flag) is not bool:
            _reject("RESPONSE_FIELD_TYPE")
        if flag:
            _reject("RESPONSE_MODEL_ERROR")
    if "error" in value:
        error = value["error"]
        if error is None or error is False:
            pass
        elif type(error) is str:
            if error.strip():
                _reject("RESPONSE_MODEL_ERROR")
        elif error is True:
            _reject("RESPONSE_MODEL_ERROR")
        else:
            _reject("RESPONSE_FIELD_TYPE")
    if "type" in value:
        kind = value["type"]
        if type(kind) is not str:
            _reject("RESPONSE_FIELD_TYPE")
        if kind == "error":
            _reject("RESPONSE_MODEL_ERROR")
        if kind != "result":
            _reject("RESPONSE_UNSUPPORTED_TYPE")


def _select(value):
    structured = value.get("structured_output")
    result = value.get("result")
    has_structured = "structured_output" in value and structured is not None
    has_result = "result" in value and result is not None
    if has_structured and has_result:
        _reject("RESPONSE_AMBIGUOUS")
    if has_structured:
        if type(structured) is not dict:
            _reject("RESPONSE_STRUCTURED_OUTPUT_INVALID")
        return structured
    if has_result:
        if type(result) is not str:
            _reject("RESPONSE_RESULT_INVALID")
        parsed = _load(result, MAX_RESULT_DEPTH, MAX_RESULT_CONTAINERS)
        if type(parsed) is not dict:
            _reject("RESPONSE_RESULT_INVALID")
        return parsed
    if ENVELOPE_KEYS & set(value):
        _reject("RESPONSE_CANDIDATE_MISSING")
    return value


def extract_model_response(raw):
    """Return canonical UTF-8 JSON bytes for the one proposal object in ``raw``."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RESPONSE_BYTES:
        _reject("RESPONSE_BOUNDS")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _reject("RESPONSE_ENCODING")
    if text.startswith("\ufeff"):
        _reject("RESPONSE_ENCODING")
    value = _load(text, MAX_OUTER_DEPTH, MAX_OUTER_CONTAINERS)
    if type(value) is not dict:
        _reject("RESPONSE_ENVELOPE")
    _check_fields(value)
    candidate = _select(value)
    if type(candidate) is not dict:
        _reject("RESPONSE_CANDIDATE")
    try:
        encoded = json.dumps(candidate, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _reject("RESPONSE_SERIALIZATION")
    if not 0 < len(encoded) <= MAX_RESPONSE_BYTES:
        _reject("RESPONSE_OUTPUT_BOUNDS")
    return encoded
