"""Own a temporary Windows PostgreSQL started under pg_ctl's restricted token."""
import subprocess


class WindowsPostgres:
    def __init__(self, tool, data, options, environment, log):
        # Python's Windows subprocess implementation uses these same owned
        # handles. Holding the handle also prevents PID reuse until close().
        import _winapi
        self.api = _winapi
        self.handle = None
        self.data = data
        self.control = [tool('pg_ctl'), '-D', str(data)]
        self.environment = environment
        self.log = log
        try:
            # pg_ctl applies PostgreSQL's restricted token on Windows. A
            # direct postgres.exe launch from runneradmin is rejected by PG.
            self.command(['-l', str(data.parent / 'postgres.log'), '-w', '-t', '15',
                          '-o', subprocess.list2cmdline(options), 'start'], 20)
            pid = int((data / 'postmaster.pid').read_text().splitlines()[0])
            self.handle = _winapi.OpenProcess(0x00100000 | 0x1000, False, pid)
            if self.poll() is not None:
                raise RuntimeError('owned Windows PostgreSQL exited during startup')
        except BaseException:
            try:
                self.command(['-m', 'fast', '-w', '-t', '15', 'stop'], 20, check=False)
            finally:
                self.close()
            raise

    def command(self, arguments, timeout, check=True):
        return subprocess.run(self.control + arguments, env=self.environment, cwd=self.data.parent,
                              stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
                              check=check, timeout=timeout)

    def poll(self):
        if self.api.WaitForSingleObject(self.handle, 0) == 0:
            return self.api.GetExitCodeProcess(self.handle)
        return None

    def wait(self, timeout):
        if self.api.WaitForSingleObject(self.handle, int(timeout * 1000)) == 258:
            raise subprocess.TimeoutExpired('owned Windows PostgreSQL', timeout)
        return self.api.GetExitCodeProcess(self.handle)

    def close(self):
        if self.handle is not None:
            self.api.CloseHandle(self.handle)
            self.handle = None
