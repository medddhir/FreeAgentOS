"""Portable controller configuration. No credentials or security policy fields."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
import os
import re
import shutil
import tomllib
from urllib.parse import urlsplit
from importlib.resources import files


class ConfigError(ValueError):
    """Fixed diagnostic codes only; never include supplied configuration."""


def absolute(value):
    if not isinstance(value, str) or not value or '\0' in value or not Path(value).is_absolute():
        raise ConfigError('CONFIG_PATH_INVALID')
    return Path(value)


@dataclass(frozen=True)
class UserPaths:
    config: Path
    data: Path
    cache: Path
    state: Path


def user_paths(env=None):
    env = os.environ if env is None else env
    home = absolute(env.get('HOME', str(Path.home())))
    def base(kind, fallback):
        override = env.get('FREEAGENTOS_' + kind + '_HOME')
        if override is not None:
            return absolute(override)
        return absolute(env.get('XDG_' + kind + '_HOME', str(home / fallback))) / 'freeagentos'
    return UserPaths(base('CONFIG', '.config'), base('DATA', '.local/share'),
                     base('CACHE', '.cache'), base('STATE', '.local/state'))


def bundled_data(name):
    if name not in ('public_apis.json', 'buildx.json', 'prompt_patterns.json'):
        raise ConfigError('RESOURCE_UNKNOWN')
    source = Path(__file__).resolve().parents[1] / 'data' / name
    return source if source.is_file() else Path(str(files('freeagentos_data').joinpath(name)))


def bundled_tools_root():
    source = Path(__file__).resolve().parents[1] / "bin"
    return source if source.is_dir() else Path(str(files("freeagentos_tools").joinpath("freeagent-test"))).parent


def bundled_tool(name):
    if name not in ('dev-intel', 'prompt-intel', 'exa-intel', 'freeagent-test', 'freeagent-run', 'freeagent-code'):
        raise ConfigError('RESOURCE_UNKNOWN')
    return bundled_tools_root() / name


@dataclass(frozen=True)
class Configuration:
    version: int = 1
    launcher: str = 'claude-free'
    endpoint: str = 'http://127.0.0.1:3001'
    credential_env: str | None = None
    attribution_enabled: bool = True
    attribution_socket: Path = Path('/run/freeagentos-attribution/gateway.sock')
    # Compatibility trust anchor, not configurable through user/model text.
    model_profiles: tuple = ()


_scope = ContextVar('freeagentos_configuration', default=None)


def local_endpoint(value):
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() for c in value):
        raise ConfigError('CONFIG_ENDPOINT_INVALID')
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError:
        raise ConfigError('CONFIG_ENDPOINT_INVALID') from None
    if (url.scheme not in ('http', 'https') or url.hostname not in ('localhost', '127.0.0.1', '::1')
            or url.username is not None or url.password is not None or url.query or url.fragment
            or url.path not in ('', '/') or port == 0):
        raise ConfigError('CONFIG_ENDPOINT_INVALID')
    return value.rstrip('/')


def load_config(path=None, *, env=None):
    env = os.environ if env is None else env
    explicit = path is not None or 'FREEAGENTOS_CONFIG' in env
    selected = absolute(str(path)) if path is not None else absolute(env['FREEAGENTOS_CONFIG']) if 'FREEAGENTOS_CONFIG' in env else user_paths(env).config / 'config.toml'
    try:
        raw = tomllib.loads(selected.read_text(encoding='utf-8'))
    except FileNotFoundError:
        if explicit:
            raise ConfigError('CONFIG_NOT_FOUND') from None
        raw = {'config_version': 1}
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise ConfigError('CONFIG_MALFORMED') from None
    if type(raw.get('config_version')) is not int or raw['config_version'] != 1:
        raise ConfigError('CONFIG_VERSION_UNSUPPORTED')
    allowed = {'config_version', 'adapter', 'attribution', 'models'}
    if set(raw) - allowed:
        raise ConfigError('CONFIG_FIELD_UNKNOWN')
    sections = {'adapter': {'launcher', 'endpoint', 'credential_env'},
                'attribution': {'enabled', 'socket'}, 'models': {'planner', 'coder', 'fixer', 'reviewer', 'researcher'}}
    for key, keys in sections.items():
        section = raw.get(key, {})
        if not isinstance(section, dict) or set(section) - keys:
            raise ConfigError('CONFIG_FIELD_UNKNOWN')
    adapter = raw.get('adapter', {}); attribution = raw.get('attribution', {})
    launcher = adapter.get('launcher', 'claude-free')
    if (not isinstance(launcher, str) or len(launcher) > 4096 or not launcher
            or '\0' in launcher or ('/' in launcher and not Path(launcher).is_absolute())
            or ('/' not in launcher and re.fullmatch(r'[A-Za-z0-9_.-]+', launcher) is None)):
        raise ConfigError('CONFIG_LAUNCHER_INVALID')
    credential = adapter.get('credential_env')
    if credential is not None and (not isinstance(credential, str) or re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', credential) is None):
        raise ConfigError('CONFIG_CREDENTIAL_REFERENCE_INVALID')
    enabled = attribution.get('enabled', True)
    if type(enabled) is not bool:
        raise ConfigError('CONFIG_TYPE_INVALID')
    models = raw.get('models', {})
    try:
        from roles.model_profiles import resolve_profile, ModelProfileError
    except ModuleNotFoundError:
        from orchestrator.roles.model_profiles import resolve_profile, ModelProfileError
    try:
        for role, profile in models.items():
            resolve_profile(role, profile)
    except ModelProfileError:
        raise ConfigError('CONFIG_MODEL_PROFILE_INVALID') from None
    return Configuration(launcher=launcher, endpoint=local_endpoint(adapter.get('endpoint', 'http://127.0.0.1:3001')),
                         credential_env=credential, attribution_enabled=enabled,
                         attribution_socket=absolute(attribution.get('socket', '/run/freeagentos-attribution/gateway.sock')),
                         model_profiles=tuple(sorted(models.items())))


def current_config():
    value = _scope.get()
    return value if value is not None else load_config()


@contextmanager
def config_scope(config):
    token = _scope.set(config)
    try:
        yield
    finally:
        _scope.reset(token)


def discover_launcher(config=None):
    config = current_config() if config is None else config
    result = shutil.which(config.launcher)
    if result is None:
        raise ConfigError('ADAPTER_LAUNCHER_UNAVAILABLE')
    return result


def adapter_environment(environment, settings):
    """Apply only validated non-secret settings; credentials remain in env memory."""
    result = dict(environment)
    result['ANTHROPIC_BASE_URL'] = local_endpoint(settings['endpoint'])
    reference = settings.get('credential_env')
    if reference:
        if re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', reference) is None:
            raise ConfigError('CONFIG_CREDENTIAL_REFERENCE_INVALID')
        if not result.get(reference):
            raise ConfigError('ADAPTER_CREDENTIAL_UNAVAILABLE')
        result['ANTHROPIC_AUTH_TOKEN'] = result[reference]
    return result

# Preserve one scoped configuration for both the existing module layout and
# installed-package imports. No environment/configuration is read at import.
import sys as _sys
_sys.modules.setdefault('foundation', _sys.modules[__name__])
_sys.modules.setdefault('orchestrator.foundation', _sys.modules[__name__])
