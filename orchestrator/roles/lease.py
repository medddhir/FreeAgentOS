"""Controller-clock, one-shot activity grace; never a retry or rolling lease."""
BASE_SECONDS = 180
GRACE_SECONDS = 60
RECENT_SECONDS = 30
HARD_SECONDS = 240
NS = 1_000_000_000
BOOL_FIELDS = ('grace_eligible', 'grace_granted', 'base_lease_exceeded', 'completed_during_grace')
INT_FIELDS = ('base_ms', 'grace_ms', 'hard_cap_ms', 'recent_window_ms')


def hard_cap_seconds(base, role, profile, streaming, ceiling):
    enabled = role in ('coder', 'fixer') and profile == 'model' and streaming is True and base == BASE_SECONDS
    return min(base + GRACE_SECONDS, HARD_SECONDS, ceiling) if enabled else base


def safe_lease(value):
    value = value if isinstance(value, dict) else {}
    result = {key: value[key] for key in BOOL_FIELDS if type(value.get(key)) is bool}
    result.update({key: value[key] for key in INT_FIELDS if type(value.get(key)) is int
                   and 0 <= value[key] <= HARD_SECONDS * 1000})
    last = value.get('last_trusted_progress_ms')
    if last is None or type(last) is int and 0 <= last <= HARD_SECONDS * 1000:
        result['last_trusted_progress_ms'] = last
    if value.get('progress_source') in ('BROKER_SUCCESS', 'STREAM_TOOL_SUCCESS', 'NONE'):
        result['progress_source'] = value['progress_source']
    return result


class ActivityLease:
    def __init__(self, base, role, profile, streaming, ceiling, started_ns):
        self.started_ns = started_ns
        self.base_ns = started_ns + int(base * NS)
        hard = hard_cap_seconds(base, role, profile, streaming, ceiling)
        self.hard_ns = started_ns + int(hard * NS)
        self.deadline_ns = self.base_ns
        self.enabled = self.hard_ns > self.base_ns
        self.decided = False
        self.granted = False
        self.eligible = False
        self.last_ns = None
        self.source = 'NONE'

    def observe(self, *, broker=None, capture=None):
        """Retain pre-deadline progress even if the next poll straddles expiry."""
        if broker is not None:
            last = broker.telemetry.last_success_ns
            source = 'BROKER_SUCCESS'
        else:
            last_ms = getattr(capture, 'last_tool_success_ms', None)
            valid = (getattr(capture, 'data', {}).get('activity_status') in ('ACTIVE', 'COMPLETE')
                     and not getattr(capture, 'truncated', False))
            last = self.started_ns + last_ms * 1_000_000 if valid and type(last_ms) is int else None
            source = 'STREAM_TOOL_SUCCESS'
        if type(last) is int and self.started_ns <= last < self.base_ns:
            self.last_ns, self.source = last, source

    def extend(self, now_ns, *, broker=None, capture=None):
        """Evaluate once at base expiry; only pre-deadline successful completions."""
        if now_ns < self.base_ns or self.decided:
            return False
        self.decided = True
        self.observe(broker=broker, capture=capture)
        if (getattr(capture, 'truncated', False) or
                getattr(capture, 'data', {}).get('activity_status') in ('INVALID', 'MODEL_ERROR')):
            return False
        recent = self.last_ns is not None and self.last_ns >= self.base_ns - RECENT_SECONDS * NS
        self.eligible = self.enabled and recent
        if self.eligible and now_ns < self.hard_ns:
            self.granted = True
            self.deadline_ns = self.hard_ns
        return self.granted

    def evidence(self, ended_ns, *, success):
        return safe_lease({
            'base_ms': (self.base_ns - self.started_ns) // 1_000_000,
            'grace_eligible': self.eligible, 'grace_granted': self.granted,
            'grace_ms': (self.hard_ns - self.base_ns) // 1_000_000 if self.granted else 0,
            'hard_cap_ms': (self.hard_ns - self.started_ns) // 1_000_000,
            'recent_window_ms': RECENT_SECONDS * 1000 if self.enabled else 0,
            'base_lease_exceeded': ended_ns > self.base_ns,
            'completed_during_grace': self.granted and success and self.base_ns < ended_ns <= self.hard_ns,
            'last_trusted_progress_ms': None if self.last_ns is None else (self.last_ns - self.started_ns) // 1_000_000,
            'progress_source': self.source})
