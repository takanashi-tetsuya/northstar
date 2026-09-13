#!/usr/bin/env python3
"""Fail a Linux fixture promptly when either of its owned sibling servers exits."""
import argparse
import os
from pathlib import Path
import select
import signal
import subprocess
import sys

from github_ci_supervisor import publish_failure_marker


def identity(pid, parent):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    if fields[0] in {'Z', 'X'} or int(fields[1]) != parent:
        raise ValueError('server must be a live child of the fixture shell')
    return int(fields[19])


def server_handle(pid, parent):
    before = identity(pid, parent)
    descriptor = os.pidfd_open(pid)
    try:
        if identity(pid, parent) != before or select.select([descriptor], [], [], 0)[0]:
            raise ValueError('server exited while binding its process handle')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def run(servers, command):
    if len(servers) != 2 or len(set(servers)) != 2 or any(pid <= 1 for pid in servers):
        raise ValueError('fixture requires two distinct server PIDs')
    interrupted = None

    def cancel(signum, _frame):
        nonlocal interrupted
        interrupted = interrupted or signum

    handlers = {sig: signal.signal(sig, cancel) for sig in (signal.SIGINT, signal.SIGTERM)}
    handles = []
    workload = None
    try:
        parent = os.getppid()
        for pid in servers:
            handles.append(server_handle(pid, parent))
        if interrupted:
            return 128 + interrupted
        if select.select(handles, [], [], 0)[0]:
            raise ValueError('server exited before fixture launch')
        # Retain the outer CI supervisor's process group, including any psql
        # descendants. Only this directly owned Popen is signalled here; the
        # fixture shell retains exclusive ownership of server cleanup.
        workload = subprocess.Popen(command)
        while True:
            if interrupted:
                publish_failure_marker('parent_cancel')
                return 128 + interrupted
            exited = select.select(handles, [], [], .05)[0]
            if exited:
                publish_failure_marker('lifecycle')
                print(f'fixture server {handles.index(exited[0]) + 1} exited during workload',
                      file=sys.stderr, flush=True)
                return 1
            code = workload.poll()
            if code is not None:
                if code:
                    publish_failure_marker('command_exit')
                return code if code >= 0 else 128 - code
    except (OSError, ValueError, IndexError):
        publish_failure_marker('lifecycle')
        print('fixture server monitor could not verify owned live processes', file=sys.stderr, flush=True)
        return 1
    finally:
        try:
            if workload is not None and workload.poll() is None:
                workload.terminate()
                try:
                    workload.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    workload.kill()
                    workload.wait(timeout=2)
        finally:
            for descriptor in handles:
                os.close(descriptor)
            for sig, handler in handlers.items():
                signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=int, action='append', required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('fixture command is required')
    return run(args.server, command)


if __name__ == '__main__':
    sys.exit(main())
