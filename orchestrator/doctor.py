"""Read-only readiness observations. Never starts workers or model sessions."""
import argparse
import http.client
import importlib.metadata as metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
from urllib.parse import urlsplit

from foundation import (ConfigError, bundled_data, bundled_tool, config_scope,
                        discover_launcher, load_config, local_endpoint, user_paths)

REQUIREMENTS = ('REQUIRED', 'OPTIONAL', 'INFORMATIONAL')
STATUSES = ('PASS', 'WARN', 'FAIL', 'SKIP')
BINARY_PATHS = {'git': '/usr/bin/git', 'unshare': None, 'setpriv': '/usr/bin/setpriv',
                'chroot': '/usr/sbin/chroot', 'system_python': '/usr/bin/python3', 'env': '/usr/bin/env'}


def read(path):
    try:
        with Path(path).open() as stream:
            return stream.read(262144)
    except (OSError, UnicodeError):
        return ''


def usable(path):
    """Test nearest existing directory with an owned, immediately removed file."""
    parent = Path(path)
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    try:
        if not parent.is_dir():
            return False
        with tempfile.TemporaryFile(dir=parent) as probe:
            probe.write(b'freeagent-doctor')
        return True
    except OSError:
        return False


def dependencies_available():
    """Check installed metadata closure; never imports model/network clients."""
    try:
        from packaging.requirements import Requirement
        from packaging.utils import canonicalize_name
        if metadata.version('langgraph') != '1.2.12':
            return False
        pending = ['langgraph']; seen = set()
        while pending:
            name = canonicalize_name(pending.pop())
            if name in seen:
                continue
            seen.add(name)
            dist = metadata.distribution(name)
            for raw in dist.requires or []:
                requirement = Requirement(raw)
                if requirement.marker is not None and not requirement.marker.evaluate({'extra': ''}):
                    continue
                if not requirement.specifier.contains(metadata.version(requirement.name), prereleases=True):
                    return False
                pending.append(requirement.name)
        return True
    except (ImportError, metadata.PackageNotFoundError, ValueError):
        return False


def health(endpoint):
    """Only unauthenticated GET /api/ping; no redirects, response body or auth."""
    endpoint = local_endpoint(endpoint)
    parsed = urlsplit(endpoint)
    client = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection
    connection = client(parsed.hostname, parsed.port, timeout=.75)
    try:
        connection.request('GET', '/api/ping')
        return connection.getresponse().status == 200
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def privileges_available():
    # The present implementation uses these capabilities directly; no delegation.
    needed = (0, 1, 6, 7, 8, 18, 21, 27)  # chown, DAC, setgid/uid/pcap, chroot, admin, mknod
    for line in read('/proc/self/status').splitlines():
        if line.startswith('CapEff:'):
            try:
                mask = int(line.split()[1], 16)
                return os.geteuid() == 0 and all(mask & (1 << bit) for bit in needed)
            except (ValueError, IndexError):
                return False
    return False


def attribution_security(config):
    """Filesystem checks only: no connect, registration, token or session."""
    from roles.model_attribution import validate_socket_path
    try:
        validate_socket_path(config.attribution_socket)
        return True
    except (OSError, ValueError):
        return False


def collect(config_path=None, target=None):
    checks = []
    def add(identifier, passed, dimension, reason, remediation, *, requirement='REQUIRED', unknown=False, detail=None):
        status = ('WARN' if unknown else 'PASS' if passed else 'FAIL')
        if requirement != 'REQUIRED' and not passed:
            status = 'WARN'
        record = {'id': identifier, 'status': status, 'requirement': requirement,
                  'dimension': dimension, 'reason': 'OK' if passed and not unknown else reason,
                  'remediation': '' if passed and not unknown else remediation}
        if detail is not None:
            record['detail'] = detail
        checks.append(record)
    root = Path(__file__).resolve().parent
    add('installation', all((root / name).is_file() for name in ('cli.py', 'state.py', 'entrypoint.py', 'roles/worker.py')),
        'core', 'INSTALLATION_INCOMPLETE', 'Reinstall the reviewed FreeAgentOS package or use a complete checkout.')
    add('python', sys.version_info >= (3, 12), 'core', 'PYTHON_VERSION_UNSUPPORTED', 'Use Python 3.12 or newer in the project virtualenv.')
    add('runtime_dependencies', dependencies_available(), 'core', 'DEPENDENCY_MISSING_OR_INCOMPATIBLE', 'Install the pinned runtime requirements into the project virtualenv; run pip check.')
    linux = platform.system() == 'Linux'
    add('operating_system', linux, 'isolation', 'OS_UNSUPPORTED', 'Use the qualified Linux environment; native macOS/Windows isolation is not implemented.')
    add('architecture', platform.machine().lower() in ('x86_64', 'amd64'), 'core', 'ARCHITECTURE_UNQUALIFIED', 'The reference target is x86_64; qualify other architectures separately.')
    for name, fixed in BINARY_PATHS.items():
        found = fixed if fixed and os.path.isfile(fixed) and os.access(fixed, os.X_OK) else shutil.which(name) if fixed is None else None
        add(name, found is not None, 'core' if name in ('git', 'system_python') else 'isolation',
            'SYSTEM_BINARY_MISSING', 'Install the distribution-provided binary at the path used by production.', detail=found or 'MISSING')
    source = 'CLI' if config_path is not None else 'ENVIRONMENT' if 'FREEAGENTOS_CONFIG' in os.environ else 'DEFAULT_LOCATION'
    config = None; config_reason = 'CONFIG_INVALID'
    try:
        config = load_config(config_path)
        if source == "DEFAULT_LOCATION":
            source = "DEFAULT_FILE" if (user_paths().config / "config.toml").is_file() else "BUILTIN_DEFAULTS"
    except ConfigError as exc:
        config_reason = str(exc)
    add('configuration', config is not None, 'core', config_reason, 'Correct the version-1 TOML configuration; do not add security overrides.', detail=source)
    add('config_version', config is not None, 'core', config_reason, 'Use config_version = 1.', detail=1 if config else 'UNAVAILABLE')
    try:
        paths = user_paths()
        add('xdg_paths', True, 'core', '', '')
        add('config_directory', usable(paths.config), 'core', 'PATH_UNWRITABLE', 'Choose an owned writable configuration directory.', requirement='INFORMATIONAL')
        add('data_cache_directories', usable(paths.data) and usable(paths.cache), 'research', 'PATH_UNWRITABLE', 'Choose owned writable data/cache directories.', requirement='OPTIONAL')
        state_ok = usable(paths.state)
    except ConfigError:
        add('xdg_paths', False, 'core', 'CONFIG_PATH_INVALID', 'Use absolute HOME/XDG/FreeAgentOS directory overrides.')
        add('config_directory', False, 'core', 'CONFIG_PATH_INVALID', 'Correct the directory configuration.', requirement='INFORMATIONAL')
        add('data_cache_directories', False, 'research', 'CONFIG_PATH_INVALID', 'Correct the directory configuration.', requirement='OPTIONAL')
        state_ok = False
    add('state_directory', state_ok, 'core', 'PATH_UNWRITABLE', 'Choose an owned writable state/evidence directory; do not broaden permissions.')
    add('workspace_root', usable(tempfile.gettempdir()), 'isolation', 'WORKSPACE_ROOT_UNUSABLE', 'Use a writable temporary root supporting owned disposable directories.')
    try:
        resources = all(bundled_data(n).is_file() for n in ('public_apis.json', 'buildx.json', 'prompt_patterns.json')) and all(bundled_tool(n).is_file() for n in ('freeagent-test', 'dev-intel', 'prompt-intel', 'exa-intel'))
    except (ImportError, OSError):
        resources = False
    add('bundled_resources', resources, 'core', 'RESOURCE_MISSING', 'Reinstall the reviewed package including bundled resources.')
    launcher = None
    if config is not None:
        try:
            launcher = discover_launcher(config)
        except ConfigError:
            pass
    candidate = launcher or (config.launcher if config and Path(config.launcher).is_absolute() else None)
    launcher_exists = bool(candidate and Path(candidate).is_file())
    add('launcher', launcher_exists, 'inference', 'LAUNCHER_MISSING', 'Install/configure a compatible Claude adapter launcher; doctor does not execute it.', detail=candidate or 'MISSING')
    add('launcher_executable', launcher is not None and os.access(launcher, os.X_OK), 'inference', 'LAUNCHER_NOT_EXECUTABLE', 'Select an executable compatible launcher; do not use a shell command string.')
    add('model_profiles', config is not None, 'inference', config_reason, 'Select only registered profiles compatible with their roles.')
    # load_config enforces scheme, loopback, absence of URL credentials and paths.
    add('endpoint_policy', config is not None, 'inference', config_reason, 'Configure an HTTP/HTTPS loopback-only endpoint without credentials in its URL.')
    add('gateway_health', config is not None and health(config.endpoint), 'inference', 'GATEWAY_UNREACHABLE', 'Check/start your approved local gateway independently; doctor never starts services.')
    add('client_compatibility', False, 'inference', 'CLIENT_COMPATIBILITY_UNPROVEN', 'Qualify the installed client against required stream/MCP/result/permission flags; no client is executed by doctor.', unknown=True)
    credential = bool(config and config.credential_env and os.environ.get(config.credential_env))
    add('credential_source', credential, 'inference', 'CREDENTIAL_SOURCE_UNPROVEN', 'Configure an environment credential reference or independently verify your trusted wrapper integration. No credential values are displayed.', unknown=not credential)
    namespace = linux and hasattr(os, 'unshare') and all(Path('/proc/self/ns/' + n).exists() for n in ('mnt', 'pid', 'net'))
    add('namespace_prerequisites', namespace, 'isolation', 'NAMESPACE_UNAVAILABLE', 'Use a Linux/Python environment with mount, PID and network namespace APIs.')
    controllers = read('/sys/fs/cgroup/cgroup.controllers').split()
    cgroup = bool(controllers) and ' - cgroup2 ' in read('/proc/self/mountinfo')
    add('cgroup_v2', cgroup, 'isolation', 'CGROUP_V2_UNAVAILABLE', 'Provide cgroup v2; retain production controls.')
    add('cgroup_controllers', {'cpu', 'memory', 'pids'} <= set(controllers), 'isolation', 'CGROUP_CONTROLLER_MISSING', 'Provide CPU, memory and pids controllers; doctor does not enable them.')
    kill_visible = Path('/sys/fs/cgroup/cgroup.kill').is_file()
    add('cgroup_kill', kill_visible, 'isolation', 'CGROUP_KILL_UNPROVEN',
        'cgroup.kill may exist only in non-root scopes. Production preflight must prove it in its disposable scope; doctor creates no cgroup.', unknown=not kill_visible)
    add('mount_chroot_prerequisites', linux and importlib.util.find_spec('ctypes') is not None and importlib.util.find_spec('resource') is not None,
        'isolation', 'ISOLATION_PREREQUISITE_MISSING', 'Use the qualified Linux libc/Python environment.')
    add('effective_privileges', privileges_available(), 'isolation', 'PRIVILEGE_INSUFFICIENT', 'Current development runtime requires privileged Linux isolation. A reviewed privilege boundary/bootstrap is future work; do not weaken controls.')
    add('active_isolation_proof', False, 'isolation', 'ACTIVE_ISOLATION_UNPROVEN', 'Production preflight must prove enforcement before any model. Read-only doctor cannot mount namespaces or create cgroups.', unknown=True)
    enabled = bool(config and config.attribution_enabled)
    secure = enabled and attribution_security(config)
    add('attribution_socket_security', secure, 'attribution', 'ATTRIBUTION_UNAVAILABLE' if enabled else 'ATTRIBUTION_DISABLED',
        'Optional: provide the private gateway socket with its established ownership/mode contract.', requirement='OPTIONAL')
    add('attribution_session_proof', False, 'attribution', 'ATTRIBUTION_SESSION_UNPROVEN',
        'Filesystem checks do not establish authenticated peer/session/dispatch evidence. Doctor never registers a session.', requirement='OPTIONAL', unknown=True)
    for name in ('curl', 'mcporter'):
        found = shutil.which(name)
        add('research_' + name, found is not None, 'research', 'OPTIONAL_BINARY_MISSING', 'Install/configure this bounded research tool only if needed.', requirement='OPTIONAL', detail=found or 'MISSING')
    add('research_service_configuration', False, 'research', 'RESEARCH_SERVICE_UNPROVEN', 'Configure optional Exa/Jina access independently; doctor does not query research services.', requirement='OPTIONAL', unknown=True)
    if target is None:
        add('target_tests', False, 'core', 'TARGET_NOT_SELECTED', 'Optionally pass --repo to inspect existing test markers; no target tests are executed.', requirement='INFORMATIONAL', unknown=True)
    else:
        path = Path(target)
        python_tests = path.is_dir() and (any(path.glob('test_*.py')) or any(path.glob('*_test.py')))
        add('target_tests', bool(python_tests), 'core', 'TARGET_TEST_DEPENDENCIES_UNPROVEN', 'Existing root Python test markers can be detected; pytest/npm dependency closure and actual verification need separate checks.', requirement='INFORMATIONAL', unknown=not python_tests)
    return summarize(checks)


def summarize(checks):
    dimensions = {}
    for dimension in ('core', 'inference', 'isolation', 'attribution', 'research'):
        subset = [c for c in checks if c['dimension'] == dimension]
        decisive = [c for c in subset if c['requirement'] == 'REQUIRED'] or subset
        dimensions[dimension] = bool(decisive) and all(c['status'] == 'PASS' for c in decisive)
    # WARN on a required proof means unknown, never safe READY.
    ready = all(c['status'] == 'PASS' for c in checks if c['requirement'] == 'REQUIRED')
    return {'schema_version': 1, 'status': 'READY' if ready else 'NOT_READY',
            'production_worker_ready': ready, 'dimensions': dimensions, 'checks': checks}


def render(result):
    lines = ['FreeAgentOS Doctor (zero generation)', '']
    for check in result['checks']:
        lines.append(f"{check['id']}: {check['status']} [{check['requirement']}] {check['reason']}")
        if 'detail' in check:
            lines.append('  ' + str(check['detail']))
        if check['remediation']:
            lines.append('  ' + check['remediation'])
    lines.extend(['', 'Overall: ' + result['status'],
                  'Read-only observations cannot certify active isolation or served model identity.'])
    return '\n'.join(lines)


class DoctorParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'freeagent: DOCTOR_USAGE_ERROR\n')


def main(argv=None):
    parser = DoctorParser(prog='freeagent')
    commands = parser.add_subparsers(dest='command', required=True)
    doctor = commands.add_parser('doctor', help='Read-only zero-generation readiness diagnostic')
    doctor.add_argument('--json', action='store_true')
    doctor.add_argument('--config', help='Absolute version-1 config path')
    doctor.add_argument('--repo', help='Optional target test-marker inspection only')
    args = parser.parse_args(argv)
    try:
        result = collect(args.config, args.repo)
    except Exception:
        result = {'schema_version': 1, 'status': 'ERROR', 'reason': 'DOCTOR_INTERNAL_ERROR'}
    print(json.dumps(result, separators=(',', ':'), sort_keys=True) if args.json else render(result) if result['status'] != 'ERROR' else 'FreeAgentOS Doctor: ERROR DOCTOR_INTERNAL_ERROR')
    return 2 if result['status'] == 'ERROR' else 0 if result['status'] == 'READY' else 1
