"""One-off guard for the reviewed pure/mocked unittest entry, not a sandbox."""
import json
import os
from pathlib import Path
import runpy
import sys

ROOT = Path('/workspace/scratch/6c1169b97236/northstar-repair')
RESULT = Path(__file__).with_name('unit-boundary-result.json')
blocked = {'os.fork', 'os.forkpty', 'os.exec', 'os.posix_spawn', 'os.spawn',
           'os.system', 'subprocess.Popen', 'os.kill', 'os.killpg',
           'resource.setrlimit', 'resource.prlimit', 'signal.pthread_kill',
           '_thread.start_new_thread'}
counts = {}
ready = False

def stop(event):
    label = event[:80]
    if label not in counts and len(counts) >= 32:
        label = 'OtherBlockedBoundary'
    counts[label] = min(counts.get(label, 0) + 1, 1000)
    raise KeyboardInterrupt('UnmockedBoundary:' + event)

def audit(event, args):
    global ready
    if event == 'northstar.unit_tripwire_ready':
        ready = True
    elif event in blocked or event.startswith('socket.') or (
        event in ('ctypes.dlsym', 'ctypes.dlsym/handle') and len(args) > 1 and args[1] == 'prctl'
    ):
        stop(event)

sys.addaudithook(audit)
sys.audit('northstar.unit_tripwire_ready')
if not ready:
    raise SystemExit('Unit audit hook was not installed')
original_exit = os._exit
os._exit = lambda *_args, **_kwargs: stop('os._exit')
script = ROOT / 'scripts/test-controlled-admission.py'
sys.path.insert(0, str(script.parent))
sys.argv = [str(script), "-v"]
code = 1
try:
    runpy.run_path(str(script), run_name='__main__')
    code = 0
except SystemExit as error:
    code = error.code if type(error.code) is int else (0 if error.code is None else 1)
except KeyboardInterrupt:
    code = 3 if counts else 130
finally:
    os._exit = original_exit
    if counts:
        code = 3
    RESULT.write_text(json.dumps({'schema': 'northstar-unit-tripwire-v1',
                                  'audit_hook_ready': ready, 'blocked_attempts': counts,
                                  'unit_exit_status': code, 'syscall_sandbox': False},
                                 indent=2, sort_keys=True) + '\n')
raise SystemExit(code)
