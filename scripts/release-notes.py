#!/usr/bin/env python3
"""Render draft release notes using only this run's verified artifact identity."""
import argparse
import json
from pathlib import Path
import re


def render(qualification, evidence, output, verified):
    q = json.loads(qualification.read_text())
    e = json.loads(evidence.read_text())
    commit, version = e['commit'], e['version']
    if (not re.fullmatch('[0-9a-f]{40}', commit) or not re.fullmatch(r'\d+\.\d+\.\d+', version)
            or q['commit'] != commit or q['tag'] != 'v' + version or e.get('published_images') is not True
            or not re.fullmatch(r'https://github.com/takanashi-tetsuya/northstar/actions/runs/[1-9][0-9]*', q['ciUrl'])
            or type(e['workflow_run_id']) is not int or e['workflow_run_id'] <= 0):
        raise ValueError('release-note evidence does not match the qualified release')
    template = Path(__file__).resolve().parents[1] / 'docs/releases' / (version + '.md')
    status = ('All automated release preparation and fresh-download checks passed. Ready for publication.'
              if verified else 'Draft verification is still running. Wait for the complete Release preparation workflow before publication.')
    content = (status + '\n\n' + template.read_text().strip() + '\n\n'
        + f'Source commit: [{commit}](https://github.com/takanashi-tetsuya/northstar/commit/{commit}).\n\n'
        + f'Full CI: [{q["ciRunId"]}]({q["ciUrl"]}), attempt {q["ciAttempt"]}. '
        + f'Build and package verification: [run {e["workflow_run_id"]}]'
        + f'(https://github.com/takanashi-tetsuya/northstar/actions/runs/{e["workflow_run_id"]}).\n\n'
        + 'Download `SHA256SUMS` and verify the matching asset checksums before execution. '
        + 'Verify GitHub build provenance with `gh attestation verify <file> --repo takanashi-tetsuya/northstar`. '
        + '`RELEASE-EVIDENCE.json` records native and container checks against this commit. '
        + '`IMAGE_DIGESTS` contains the three immutable image references; each image includes an SBOM and build provenance.\n')
    output.write_text(content)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verified', action='store_true')
    args = parser.parse_args()
    render(args.qualification, args.evidence, args.output, args.verified)
