#!/usr/bin/env python3
"""Lists test selectors in the CI and database scripts that select nothing. A moved test leaves a stale `cargo test`
filter behind, which runs nothing and exits 0. A filter inside a `--bin rust-xmpp-server` command must match a test of
that binary, not merely a test of the same name that moved to a crate.

Usage: selectors.py <checkout> <ws.tests> <ws.ignored>
"""
import glob, os, re, sys

BIN = '--bin rust-xmpp-server'
root = os.path.abspath(sys.argv[1])
names, root_names = set(), set()
for path in sys.argv[2:4]:
    for line in open(path, encoding='utf-8'):
        binary, name = line.strip().split(':', 1)
        names.add(name)
        if binary == 'rust_xmpp_server':
            root_names.add(name)
TOKEN = re.compile(r'(?<![\w:./-])[a-z_][a-z0-9_]*(?:::[a-z_][a-z0-9_]*)+(?![\w:(<])')
files = glob.glob(os.path.join(root, 'scripts/*.sh')) + glob.glob(os.path.join(root, 'scripts/lib/*.sh')) \
    + glob.glob(os.path.join(root, '.github/workflows/*'))
stale = 0
for path in sorted(files):
    lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    command = ''
    for number, line in enumerate(lines, 1):
        # A backslash continuation keeps one shell command, so --bin can sit on another line than the filter.
        whole = command + line
        command = whole[:-1] + ' ' if line.endswith('\\') else ''
        if command:
            continue
        pool = root_names if BIN in whole else names
        for token in TOKEN.findall(whole):
            if token.endswith(('::text', '::oid', '::pg_catalog')) or token.startswith(('tokio::', 'rust_xmpp_server::')):
                continue  # SQL casts, library paths in embedded code, log targets
            if not any(token in name for name in pool):
                stale += 1
                print(f'{os.path.relpath(path, root)}:{number}: {token}')
print(f'selectors: {stale} match no test')
