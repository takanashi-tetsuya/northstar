import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyJobResults, verifyWorkflowCoverage } from './ci-required-policy.mjs';

try {
  const workflow = fs.readFileSync(fileURLToPath(new URL('../.github/workflows/ci.yml', import.meta.url)), 'utf8')
    .replaceAll('\r\n', '\n');
  verifyWorkflowCoverage(workflow);
  if (!process.argv.includes('--workflow-only')) {
    const count = verifyJobResults(process.env.GITHUB_EVENT_NAME, JSON.parse(process.env.CI_REQUIRED_NEEDS ?? 'null'));
    const summary = `CI required: all ${count} jobs satisfy the ${process.env.GITHUB_EVENT_NAME} policy.\n`;
    process.stdout.write(summary);
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
