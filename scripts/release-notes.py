#!/usr/bin/env python3
"""Render draft release notes using only this run's verified artifact identity."""
import argparse
import json
from pathlib import Path
import re


def render(qualification, evidence, output, verified, verification_run=None):
    q = json.loads(qualification.read_text())
    e = json.loads(evidence.read_text())
    commit, version = e['commit'], e['version']
    if (not re.fullmatch('[0-9a-f]{40}', commit) or not re.fullmatch(r'\d+\.\d+\.\d+', version)
            or q['commit'] != commit or q['tag'] != 'v' + version or e.get('published_images') is not True
            or not re.fullmatch(r'https://github.com/takanashi-tetsuya/northstar/actions/runs/[1-9][0-9]*', q['ciUrl'])
            or type(e['workflow_run_id']) is not int or e['workflow_run_id'] <= 0
            or (verification_run is not None and (type(verification_run) is not int or verification_run <= 0))):
        raise ValueError('release-note evidence does not match the qualified release')
    template = Path(__file__).resolve().parents[1] / 'docs/releases' / (version + '.md')
    status = '' if verified else 'Draft verification is still running. Wait for it to finish before publication.\n\n'
    content = status + template.read_text().strip() + '\n\n<details>\n<summary>Build verification</summary>\n\n'
    if verified:
        content += 'Package and fresh-download checks passed.\n\n'
    content += (f'[Source commit](https://github.com/takanashi-tetsuya/northstar/commit/{commit}) · '
        + f'[CI]({q["ciUrl"]}), attempt {q["ciAttempt"]} · '
        + f'[Build](https://github.com/takanashi-tetsuya/northstar/actions/runs/{e["workflow_run_id"]}).\n\n'
        + '`SHA256SUMS` lists the asset checksums. `RELEASE-EVIDENCE.json` records the '
        + 'source commit and platform checks; `IMAGE_DIGESTS` lists the container digests. '
        + 'To verify build provenance, run '
        + '`gh attestation verify <file> --repo takanashi-tetsuya/northstar`.\n')
    if verification_run is not None and verification_run != e['workflow_run_id']:
        content += ('\nDraft preparation and fresh-download verification: '
                    f'[run {verification_run}](https://github.com/takanashi-tetsuya/northstar/actions/runs/{verification_run}).\n')
    content += '\n</details>\n'
    output.write_text(content)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verified', action='store_true')
    parser.add_argument('--verification-run', type=int)
    args = parser.parse_args()
    render(args.qualification, args.evidence, args.output, args.verified, args.verification_run)
