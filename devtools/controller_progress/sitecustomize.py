"""Explicit developer injection; activate only the actual controller discovery child."""
import os
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if (Path.cwd() == ROOT and Path(sys.prefix) == ROOT/'.venv-orchestrator'
        and sys.orig_argv[1:] == ['-m', 'unittest', 'discover']
        and os.environ.get('FREEAGENT_CONTROLLER_PROGRESS_DIR')):
    with open('/proc/%d/cmdline' % os.getppid(), 'rb') as parent:
        args = parent.read(4096).split(b'\0')
    if str(ROOT/'bin/freeagent-test').encode() in args:
        from progress import install
        install(Path(os.environ.pop('FREEAGENT_CONTROLLER_PROGRESS_DIR')))
        # Do not propagate this development injection to copied target runners.
        os.environ['PYTHONPATH'] = os.pathsep.join(p for p in os.environ.get('PYTHONPATH','').split(os.pathsep)
                                                if p != str(Path(__file__).parent))
