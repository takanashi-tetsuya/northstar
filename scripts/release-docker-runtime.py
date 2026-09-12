"""Own one disposable release-image container on a CI runner's loopback network."""
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import uuid


class Container:
    # The packaged server is PID 1 after the image entrypoint's exec. The
    # docker attach client has a different host PID and is never substituted.
    pid = 1

    def __init__(self, image, environment, cert, key, log, arguments=()):
        if not re.fullmatch(r'(?:ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}|northstar-release-test:[0-9a-f]{40})', image):
            raise ValueError('container smoke requires an immutable digest or exact-commit local test tag')
        self.id = None
        self.attach = None
        name = 'northstar-release-' + uuid.uuid4().hex
        env = {k: v for k, v in environment.items() if k.isupper() and k not in {
            'PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'HOME', 'USERPROFILE',
            'APPDATA', 'LOCALAPPDATA', 'LD_LIBRARY_PATH', 'LANG', 'LC_ALL'}}
        env.update(TLS_CERT_PATH='/data/server.crt', TLS_KEY_PATH='/data/server.key',
                   LOG_DIR='/data/logs', UPLOAD_DIR='/data/uploads',
                   TEST_READINESS_FILE='/data/logs/ready.json')
        command = ['docker', 'create', '--name', name, '--network', 'host']
        for k, v in sorted(env.items()):
            command += ['--env', f'{k}={v}']
        # Keep the actual image USER, WORKDIR and ENTRYPOINT. The migration
        # uses the same executable through that entrypoint as normal startup.
        command += [image, '/usr/local/bin/xmpp-server', *arguments]
        try:
            self.id = subprocess.check_output(command, text=True, timeout=30).strip()
            if not re.fullmatch('[0-9a-f]{64}', self.id):
                raise RuntimeError('docker did not return an owned container ID')
            with io.BytesIO() as stream:
                with tarfile.open(fileobj=stream, mode='w') as tar:
                    for path, filename in ((cert, 'server.crt'), (key, 'server.key')):
                        data = Path(path).read_bytes()
                        member = tarfile.TarInfo(filename)
                        member.size, member.uid, member.gid, member.mode = len(data), 10001, 10001, 0o600
                        tar.addfile(member, io.BytesIO(data))
                # Archive ownership makes private test keys readable by the
                # image's real UID without a root entrypoint or host chown.
                subprocess.run(['docker', 'cp', '-a', '-', self.id + ':/data'],
                    input=stream.getvalue(), check=True, capture_output=True, timeout=15)
            self.attach = subprocess.Popen(['docker', 'start', '--attach', self.id],
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        except BaseException:
            self.close()
            raise

    def poll(self):
        return self.attach.poll()

    def wait(self, timeout):
        status = self.attach.wait(timeout=timeout)
        if status:
            raise subprocess.CalledProcessError(status, ['docker', 'start', '--attach', self.id])

    def record(self):
        result = subprocess.run(['docker', 'exec', self.id, 'cat', '/data/logs/ready.json'],
            capture_output=True, timeout=2)
        if result.returncode:
            if self.poll() is not None:
                raise RuntimeError('owned release container exited before readiness')
            raise FileNotFoundError('container readiness record is not published yet')
        if len(result.stdout) > 8192:
            raise ValueError('container readiness record exceeded size bound')
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError('container readiness record must be an object')
        return value

    def healthcheck(self, address):
        subprocess.run(['docker', 'exec', self.id, '/usr/local/bin/xmpp-server', '--healthcheck', address],
            check=True, capture_output=True, timeout=5)

    def close(self):
        if self.id is not None and re.fullmatch('[0-9a-f]{64}', self.id):
            try:
                if self.attach is not None and self.attach.poll() is None:
                    subprocess.run(['docker', 'stop', '--time', '15', self.id],
                                   check=True, capture_output=True, timeout=20)
                    self.attach.wait(timeout=5)
            finally:
                subprocess.run(['docker', 'rm', '--force', self.id],
                               check=True, capture_output=True, timeout=15)
                if self.attach is not None and self.attach.poll() is None:
                    self.attach.wait(timeout=5)
                self.id = None
