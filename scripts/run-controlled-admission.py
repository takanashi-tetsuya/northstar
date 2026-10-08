#!/usr/bin/env python3
"""Dedicated Linux owner; source only until separately authorized to execute.

Invoke with an isolated, no-site, no-bytecode Python interpreter (-I -S -B).
The caller supplies an external trusted contract, captures bounded stdout and
the actual exit status, and checks the total invocation interval. Internal
startup_ms is not an independent interpreter-startup bound. This
entry point never builds a binary, starts a service, or selects arbitrary work.
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import controlled_admission_supervision as supervision


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract-json', required=True, help='externally trusted compact JSON, not a corpus-derived contract')
    parser.add_argument('--contract-sha256', required=True, help='external canonical-contract SHA256')
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--mode', required=True, choices=('record', 'replay'))
    parser.add_argument('--profile', choices=(supervision.DIRECT_PROFILE, supervision.NO_FLUSH_PROFILE,
                                            *supervision.COMPOSITION_PROFILES))
    args = parser.parse_args(argv)
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        parser.error('the dedicated owner requires python3 -I -S -B')
    return supervision.owner_main(args.contract_json.encode(), run_id=args.run_id,
                                  mode=args.mode, contract_sha256=args.contract_sha256,
                                  profile_id=args.profile or supervision.LEGACY_PROFILE)


if __name__ == '__main__':
    raise SystemExit(main())
