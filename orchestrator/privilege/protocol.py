"""Strict bounded records; never deserialize executable objects or echo input."""
import json
import re
import socket
import struct
import time

VERSION = 1
BUILD = 'stage31b-simulation-v1'
MAX_FRAME = 16384
MAX_REQUESTS = 128
MAX_CLIENTS = 8
MAX_RATE = 32
MAX_ENTRIES = 128
MAX_JOURNAL = 256*1024
MAX_ACTIVE = 16
MAX_PER_UID = 2
TIMEOUT = 1.0
# Absolute authenticated connection ceiling; never renewed by RPC activity.
# Allows preparation + one 240s worker + observation/release without polling.
AUTHENTICATED_LIFETIME = 600.0
IDLE_POLL = 0.1
OPERATIONS = ('HELLO', 'CREATE', 'START', 'STATUS', 'TERMINATE', 'RELEASE', 'PROBE')
CODES = frozenset(('OK', 'PROTOCOL_MISMATCH', 'AUTH_FAILED', 'PEER_NOT_ALLOWED',
    'INVALID_REQUEST', 'INVALID_STATE', 'UNKNOWN_HANDLE', 'POLICY_REJECTED',
    'RESOURCE_LIMIT_INVALID', 'PATH_REJECTED', 'EXECUTION_CLASS_REJECTED',
    'BACKEND_FAILURE', 'CLEANUP_INCOMPLETE', 'BOUNDS_EXCEEDED', 'JOURNAL_INVALID',
    'RECOVERY_REQUIRED', 'TRANSPORT_FAILURE'))
STATES = ('CREATING', 'CREATED', 'RUNNING', 'TERMINATING', 'TERMINATED', 'RELEASED', 'FAILED_DIRTY')


class BoundaryError(Exception):
    def __init__(self, code):
        self.code = code if code in CODES else 'BACKEND_FAILURE'
        super().__init__(self.code)


def identifier(value, size=32):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None


def keys(value, required, optional=()):
    if type(value) is not dict or set(value) - set(required) - set(optional) or not set(required) <= set(value):
        raise BoundaryError('INVALID_REQUEST')


def _bounded(value, depth=0):
    if depth > 4:
        raise BoundaryError('BOUNDS_EXCEEDED')
    if type(value) is dict:
        if len(value) > 32:
            raise BoundaryError('BOUNDS_EXCEEDED')
        for k, v in value.items():
            if type(k) is not str or len(k.encode()) > 64:
                raise BoundaryError('INVALID_REQUEST')
            _bounded(v, depth+1)
    elif type(value) is list:
        if len(value) > 32:
            raise BoundaryError('BOUNDS_EXCEEDED')
        for v in value:_bounded(v, depth+1)
    elif type(value) is str:
        if len(value.encode()) > 256 or '\0' in value:
            raise BoundaryError('BOUNDS_EXCEEDED')
    elif value is not None and type(value) not in (bool, int):
        raise BoundaryError('INVALID_REQUEST')
    elif type(value) is int and not 0 <= value <= 2**63-1:
        raise BoundaryError('INVALID_REQUEST')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:raise BoundaryError('INVALID_REQUEST')
        result[key] = value
    return result


def decode(raw):
    if not raw or len(raw) > MAX_FRAME:raise BoundaryError('BOUNDS_EXCEEDED')
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
        _bounded(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise BoundaryError('INVALID_REQUEST') from None


def encode(value):
    _bounded(value)
    raw = json.dumps(value, separators=(',', ':'), sort_keys=True).encode()
    if len(raw) > MAX_FRAME:raise BoundaryError('BOUNDS_EXCEEDED')
    return raw


def validate_request(value):
    _bounded(value)
    keys(value, ('version','seq','op','args'))
    if type(value['version']) is not int or value['version'] != VERSION:raise BoundaryError('PROTOCOL_MISMATCH')
    if type(value['seq']) is not int or not 1 <= value['seq'] <= MAX_REQUESTS:raise BoundaryError('INVALID_REQUEST')
    op = value['op']
    if type(op) is not str or op not in OPERATIONS:raise BoundaryError('INVALID_REQUEST')
    args = value['args']
    fields = {'HELLO':('enrollment','token','challenge','build','policy'),
              'CREATE':('run_id','slot','class','role','limits'), 'START':('handle',),
              'STATUS':('handle',), 'TERMINATE':('handle',), 'RELEASE':('handle',), 'PROBE':('probe',)}
    keys(args, fields[op])
    for key in ('handle','run_id','enrollment','challenge'):
        if key in args and not identifier(args[key]):raise BoundaryError('INVALID_REQUEST')
    if op == 'HELLO' and (not identifier(args['token'],64) or not identifier(args['policy'],64)
                          or type(args['build']) is not str):raise BoundaryError('INVALID_REQUEST')
    if op == 'CREATE':
        if type(args['slot']) is not str or re.fullmatch('[a-z][a-z0-9_-]{0,31}',args['slot']) is None:
            raise BoundaryError('PATH_REJECTED')
        if type(args['class']) is not str or type(args['role']) is not str or type(args['limits']) is not dict:
            raise BoundaryError('INVALID_REQUEST')
    if op == 'PROBE' and args['probe'] != 'BOUNDARY_V1':raise BoundaryError('INVALID_REQUEST')
    return value


def _read_exact(channel, count, deadline):
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:raise BoundaryError('TRANSPORT_FAILURE')
        channel.settimeout(remaining)
        part = channel.recv(count-len(data))
        if not part:raise BoundaryError('TRANSPORT_FAILURE')
        data.extend(part)
    return bytes(data)


def receive(channel, *, idle_deadline=None, clock=time.monotonic, stop=None):
    try:
        if idle_deadline is None:
            deadline = time.monotonic()+TIMEOUT
            header = _read_exact(channel,4,deadline)
        else:
            # Authenticated silence is not a partial frame. Poll only the local
            # socket/stop flag, without generating RPCs or renewing any lease.
            while True:
                remaining = idle_deadline-clock()
                if remaining <= 0 or stop is not None and stop.is_set():
                    raise BoundaryError('TRANSPORT_FAILURE')
                channel.settimeout(min(IDLE_POLL,remaining))
                try:first = channel.recv(1)
                except socket.timeout:continue
                if not first:raise BoundaryError('TRANSPORT_FAILURE')
                # Once any byte arrives, the entire header/body has one fixed
                # deadline. Trickle traffic cannot reset it or extend lifetime.
                remaining = idle_deadline-clock()
                if remaining <= 0:raise BoundaryError('TRANSPORT_FAILURE')
                deadline = time.monotonic()+min(TIMEOUT,remaining)
                header = first+_read_exact(channel,3,deadline)
                break
        size = struct.unpack('!I',header)[0]
        if not 1 <= size <= MAX_FRAME:raise BoundaryError('BOUNDS_EXCEEDED')
        return decode(_read_exact(channel,size,deadline))
    except (OSError, struct.error):raise BoundaryError('TRANSPORT_FAILURE') from None


def send(channel, value):
    raw=encode(value)
    try:
        channel.settimeout(TIMEOUT)
        channel.sendall(struct.pack('!I',len(raw))+raw)
    except OSError:raise BoundaryError('TRANSPORT_FAILURE') from None


def response(seq, code, data=None):
    if code not in CODES:raise BoundaryError('INVALID_REQUEST')
    return {'version':VERSION,'seq':seq,'code':code,'data':{} if data is None else data}


def validate_response(value, seq):
    keys(value,('version','seq','code','data'))
    if value['version'] != VERSION or type(value['version']) is not int or value['seq'] != seq or type(value['seq']) is not int:
        raise BoundaryError('PROTOCOL_MISMATCH')
    if type(value['code']) is not str or value['code'] not in CODES or type(value['data']) is not dict:
        raise BoundaryError('INVALID_REQUEST')
    if value['code'] != 'OK':
        if value['data']:raise BoundaryError('INVALID_REQUEST')
        raise BoundaryError(value['code'])
    return value['data']
