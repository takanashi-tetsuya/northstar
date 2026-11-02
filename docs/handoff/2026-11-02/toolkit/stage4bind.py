#!/usr/bin/env python3
"""Compares the public100 source bindings with the tree; --rebind rewrites stale bindings.

Usage: stage4bind.py <worktree> [--rebind]
"""
import ast
import hashlib
import pathlib
import re
import sys

W = pathlib.Path(sys.argv[1]).resolve()
script = W / "scripts/test-stage4-public-regressions.py"
text = script.read_text()
m = re.search(r"^_SOURCE_BINDINGS = (.*)$", text, re.M)
bindings = ast.literal_eval(m.group(1))
stale = 0
for relative, size, digest in bindings:
    raw = (W / relative).read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if len(raw) == size and actual == digest:
        continue
    stale += 1
    print(f"stage4 binding stale: {relative}: {size} -> {len(raw)}")
    if "--rebind" in sys.argv:
        old = f"('{relative}', {size}, '{digest}')"
        if text.count(old) != 1:
            sys.exit(f"{old} occurs {text.count(old)} times")
        text = text.replace(old, f"('{relative}', {len(raw)}, '{actual}')")
if "--rebind" in sys.argv:
    script.write_text(text)
print(f"stage4 bindings: {len(bindings)} files, {stale} stale")
sys.exit(1 if stale and "--rebind" not in sys.argv else 0)
