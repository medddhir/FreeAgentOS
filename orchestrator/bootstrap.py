"""User-only checkout bootstrap. Never launches a worker or configures a provider."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import venv
import tomllib

from foundation import user_paths, ConfigError


class BootstrapError(Exception):
    def __init__(self, code, reason):
        self.code, self.reason = code, reason


def platform_id():
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
        raise BootstrapError(3, 'PLATFORM_UNSUPPORTED')
    values = platform.freedesktop_os_release()
    if values.get('ID') != 'ubuntu' or values.get('VERSION_ID') != '24.04':
        raise BootstrapError(3, 'PLATFORM_UNSUPPORTED')
    release = platform.release().lower()
    return 'linux-wsl2' if 'microsoft' in release and 'wsl2' in release else 'linux-ubuntu-24.04'


def layout():
    paths = user_paths()
    root = paths.data / 'installation'
    return paths, root, root / 'venv', Path(os.environ['HOME']) / '.local/bin/freeagent'


def identity(source):
    digest = hashlib.sha256()
    selected = [source/'pyproject.toml', source/'requirements.lock', source/'requirements-build.lock']
    selected += sorted((source/'orchestrator').rglob('*.py'))
    selected += sorted((source/'data').glob('*.json'))
    selected += sorted(p for p in (source/'bin').iterdir() if p.is_file())
    for path in selected:
        digest.update(str(path.relative_to(source)).encode())
        digest.update(path.read_bytes())
    commit = subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'], capture_output=True, text=True)
    sha = commit.stdout.strip() if commit.returncode == 0 else ''
    if len(sha) != 40 or any(c not in '0123456789abcdef' for c in sha):
        sha = 'UNAVAILABLE'
    return {'schema_version': 1, 'source_commit': sha, 'source_hash': digest.hexdigest(),
            'package_version': tomllib.loads((source/'pyproject.toml').read_text())['project']['version']}


def execute(argv, code=5):
    # Suppress transport/build output: it can include private index credentials.
    result = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode:
        raise BootstrapError(code, 'DEPENDENCY_INSTALL_FAILED' if code == 5 else 'INSTALLATION_INVALID')


def doctor(command):
    result = subprocess.run([str(command), 'doctor'])
    return {0: 'READY', 1: 'NOT_READY', 2: 'ERROR'}.get(result.returncode, 'ERROR')


def install(source, dry=False):
    if sys.version_info < (3, 12):
        raise BootstrapError(4, 'PYTHON_UNSUPPORTED')
    if os.geteuid() == 0:
        raise BootstrapError(4, 'NON_ROOT_USER_REQUIRED')
    target_platform = platform_id()
    if not shutil.which('git'):
        raise BootstrapError(4, 'GIT_MISSING')
    if not __import__('importlib.util', fromlist=['find_spec']).find_spec('ensurepip'):
        raise BootstrapError(4, 'VENV_SUPPORT_MISSING')
    paths, root, env, command = layout()
    record = identity(source)
    plan = {'platform': target_platform, 'python': sys.executable, 'install_root': str(root),
            'venv': str(env), 'command': str(command), 'directories': [str(p) for p in
             (paths.config, paths.data, paths.cache, paths.state)],
            'dependencies': ['requirements-build.lock', 'requirements.lock'],
            'doctor_command': [str(command), 'doctor'], 'source': record}
    if dry:
        return dict(plan, installation='DRY_RUN')
    # Reject redirected destinations without changing pre-existing permissions.
    for destination in (root, command, paths.config, paths.cache, paths.state):
        for ancestor in (destination, *destination.parents):
            if ancestor.is_symlink() and ancestor != command:
                raise BootstrapError(6, 'DESTINATION_UNSAFE')
    if root.exists() or root.is_symlink():
        try:
            existing = json.loads((root/'installation.json').read_text())
        except (OSError, ValueError):
            raise BootstrapError(6, 'EXISTING_INSTALLATION_UNRECOGNIZED') from None
        if existing != record or not command.is_symlink() or command.resolve() != env/'bin/freeagent':
            raise BootstrapError(6, 'EXISTING_INSTALLATION_CONFLICT')
        execute([str(env/'bin/python'), '-m', 'pip', 'check'], 7)
        return dict(plan, installation='ALREADY_INSTALLED', doctor=doctor(command))
    if command.exists() or command.is_symlink():
        raise BootstrapError(6, 'LAUNCHER_CONFLICT')
    created_root = False
    published = False
    try:
        for directory in (paths.config, paths.data, paths.cache, paths.state, command.parent):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if directory.is_symlink() or directory.stat().st_uid != os.geteuid():
                raise BootstrapError(6, 'DESTINATION_UNSAFE')
        root.mkdir(mode=0o700)
        created_root = True
        try:
            venv.EnvBuilder(with_pip=True).create(env)
        except Exception:
            raise BootstrapError(4, 'VENV_CREATION_FAILED') from None
        python = str(env/'bin/python')
        execute([python, '-m', 'pip', 'install', '-r', str(source/'requirements-build.lock'),
                 '-r', str(source/'requirements.lock')])
        # Build a disposable source copy so setuptools never writes into checkout.
        with tempfile.TemporaryDirectory(prefix='freeagentos-build-') as tmp:
            copy = Path(tmp)/'source'
            copy.mkdir()
            shutil.copyfile(source/'pyproject.toml', copy/'pyproject.toml')
            for name in ('orchestrator', 'data', 'bin'):
                shutil.copytree(source/name, copy/name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            execute([python, '-m', 'pip', 'install', '--no-deps', '--no-build-isolation', str(copy)])
        execute([python, '-m', 'pip', 'check'])
        (root/'installation.json').write_text(json.dumps(record, sort_keys=True)+'\n')
        (root/'installation.json').chmod(0o600)
        if not (env/'bin/freeagent').is_file():
            raise BootstrapError(7, 'CONSOLE_MISSING')
        command.symlink_to(env/'bin/freeagent')
        published = True
        return dict(plan, installation='SUCCESS', doctor=doctor(command))
    except BaseException:
        if published:
            command.unlink()
        if created_root:
            shutil.rmtree(root)
        raise


def main():
    parser = argparse.ArgumentParser(description='User-only FreeAgentOS bootstrap; no generation.')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        result = install(Path(__file__).resolve().parents[1], args.dry_run)
        print(json.dumps(result, sort_keys=True))
        if str(Path(result['command']).parent) not in os.environ.get('PATH', '').split(os.pathsep):
            print('PATH: Add "$HOME/.local/bin" to PATH; shell startup files were not modified.')
        return 0
    except BootstrapError as error:
        guidance = {
            'NON_ROOT_USER_REQUIRED': 'Run the bootstrap as a normal non-root user, without sudo.',
            'PYTHON_UNSUPPORTED': 'Install Python 3.12+ manually.',
            'VENV_SUPPORT_MISSING': 'Install matching Python venv support manually; Ubuntu: python3.12-venv.',
            'VENV_CREATION_FAILED': 'Check matching Python venv support and available disk space.',
            'GIT_MISSING': 'Install Git manually before bootstrap.',
            'DEPENDENCY_INSTALL_FAILED': 'Check package-index connectivity and the recorded dependency pins.',
            'EXISTING_INSTALLATION_CONFLICT': 'Preserve the existing installation; automatic upgrades are not implemented.',
            'EXISTING_INSTALLATION_UNRECOGNIZED': 'Inspect the existing program directory; user data must not be deleted.',
            'LAUNCHER_CONFLICT': 'Preserve the existing launcher and resolve the conflict manually.'
        }.get(error.reason, 'Inspect user destination permissions and installation prerequisites.')
        print(json.dumps({'installation': 'FAILED', 'reason': error.reason, 'remediation': guidance}))
        return error.code
    except (OSError, ConfigError):
        print('{"installation":"FAILED","reason":"FILESYSTEM_OR_PATH_ERROR"}')
        return 6
    except Exception:
        print('{"installation":"FAILED","reason":"INTERNAL_ERROR"}')
        return 7


if __name__ == '__main__':
    raise SystemExit(main())
