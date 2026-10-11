#!/usr/bin/env node
/**
 * Run the offline CI steps of .github/workflows/ci.yml against a checkout.
 *
 * Usage: node scripts/run-ci-offline.mjs [--checkout <dir>] [--logs <dir>] [--list] [--only <substring>]
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { repositoryRoot } from './lib/source-module.mjs';

export const SELECTED_STEPS = {
  'web-static': { keep: null, skip: null },
  'rust-quality': { keep: null, skip: new Set(['Install pinned Rust 1.97.1 tools']) },
  'protocol-fuzz': { keep: new Set(['Verify fuzz targets exercise production parsers']), skip: null }
};

export const LOCAL_STEPS = [
  {
    name: 'muc-cluster-wsl-static',
    script: "sed -e '/^redis_dir=/,$d' -e 's|^project_dir=.*|project_dir=\"$PWD\"|' scripts/muc-cluster-wsl.sh | bash\n"
  }
];

export function parseWorkflowJobs(text) {
  const jobs = new Map();
  const lines = text.split('\n');
  let currentJobName = null;
  let currentJob = null;
  let inJobs = false;
  
  const stripQuotes = (str) => {
    str = str.trim();
    if (str.startsWith('"') && str.endsWith('"')) return str.slice(1, -1);
    if (str.startsWith("'") && str.endsWith("'")) return str.slice(1, -1);
    return str;
  };

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim() === '') { i++; continue; }
    
    if (line === 'jobs:') {
      inJobs = true;
      i++;
      continue;
    }
    
    if (inJobs && !line.startsWith(' ') && line.trim() !== '') {
      inJobs = false;
    }
    
    if (inJobs) {
      const jobMatch = line.match(/^  ([A-Za-z0-9_-]+):/);
      if (jobMatch) {
        currentJobName = jobMatch[1];
        currentJob = { env: {} };
        jobs.set(currentJobName, currentJob);
        i++;
        continue;
      }
      
      if (currentJobName && line === '    env:') {
        i++;
        while (i < lines.length && (lines[i].startsWith('      ') || lines[i].trim() === '')) {
          if (lines[i].trim() !== '') {
            const m = lines[i].match(/^      ([A-Za-z0-9_-]+):\s*(.*)/);
            if (m) currentJob.env[m[1]] = stripQuotes(m[2]);
          }
          i++;
        }
        continue;
      }
      
      if (currentJobName && line === '    steps:') {
        currentJob.steps = [];
        i++;
        while (i < lines.length && (lines[i].startsWith('      ') || lines[i].trim() === '')) {
          if (lines[i].trim() === '') { i++; continue; }
          
          if (lines[i].startsWith('      - ')) {
            const step = { other: [] };
            currentJob.steps.push(step);
            
            const inline = lines[i].substring(8);
            if (inline.trim() !== '') {
               const m = inline.match(/^([a-zA-Z0-9_-]+):\s*(.*)/);
               if (m) {
                 const key = m[1];
                 const val = m[2];
                 if (key === 'name') step.name = stripQuotes(val);
                 else if (key === 'run') { step.run = val; step.runStyle = 'inline'; }
                 else if (key === 'working-directory') step.workingDirectory = val.trim();
                 else step.other.push(key);
               } else {
                 step.other.push(inline.split(':')[0].trim());
               }
            }
            i++;
            
            while (i < lines.length && (lines[i].startsWith('        ') || lines[i].trim() === '')) {
               if (lines[i].trim() === '') { i++; continue; }
               
               if (lines[i] === '        env:') {
                 step.env = {};
                 i++;
                 while (i < lines.length && (lines[i].startsWith('          ') || lines[i].trim() === '')) {
                   if (lines[i].trim() !== '') {
                     const em = lines[i].match(/^          ([A-Za-z0-9_-]+):\s*(.*)/);
                     if (em) step.env[em[1]] = stripQuotes(em[2]);
                   }
                   i++;
                 }
                 continue; 
               }
               
               const lineContent = lines[i].substring(8);
               const m = lineContent.match(/^([a-zA-Z0-9_-]+):\s*(.*)/);
               if (m) {
                 const key = m[1];
                 let val = m[2];
                 
                 if (key === 'name') step.name = stripQuotes(val);
                 else if (key === 'working-directory') step.workingDirectory = val.trim();
                 else if (key === 'run') {
                   if (val.trim() === '|') {
                     step.runStyle = 'block';
                     i++;
                     const runLines = [];
                     let firstIndent = -1;
                     while (i < lines.length) {
                       if (lines[i].trim() === '') {
                         runLines.push('');
                         i++;
                         continue;
                       }
                       const indent = lines[i].match(/^ */)[0].length;
                       if (indent <= 8) break; 
                       if (firstIndent === -1) firstIndent = indent;
                       runLines.push(lines[i].substring(firstIndent));
                       i++;
                     }
                     step.run = runLines.join('\n') + '\n';
                     continue;
                   } else {
                     step.runStyle = 'inline';
                     step.run = val.trim();
                   }
                 } else {
                   step.other.push(key);
                 }
               }
               i++;
            }
            continue;
          } else {
             break;
          }
        }
        continue;
      }
    }
    i++;
  }
  return jobs;
}

export function selectSteps(jobs) {
  const steps = [];
  
  for (const [jobName, rule] of Object.entries(SELECTED_STEPS)) {
    if (!jobs.has(jobName)) {
      throw new Error(`Selected job missing: ${jobName}`);
    }
    const job = jobs.get(jobName);
    if (!job.steps) {
      throw new Error(`Selected job ${jobName} has no steps list`);
    }
    const jobEnv = job.env || {};
    
    const jobStepNames = new Set(job.steps.map(s => s.name).filter(Boolean));
    
    if (rule.skip) {
      for (const skipName of rule.skip) {
        if (!jobStepNames.has(skipName)) {
          throw new Error(`Selected step name to skip missing in job ${jobName}: ${skipName}`);
        }
      }
    }
    if (rule.keep) {
      for (const keepName of rule.keep) {
        if (!jobStepNames.has(keepName)) {
          throw new Error(`Selected step name to keep missing in job ${jobName}: ${keepName}`);
        }
      }
    }

    for (let index = 0; index < job.steps.length; index++) {
      const step = job.steps[index];
      if (step.run === undefined) continue;
      
      if (rule.skip && step.name && rule.skip.has(step.name)) continue;
      if (rule.keep && (!step.name || !rule.keep.has(step.name))) continue;
      
      if (step.other.includes('if') || step.other.includes('shell')) {
        throw new Error(`Step ${jobName}.${index} has 'if' or 'shell' key`);
      }
      
      if (step.runStyle === 'inline' && (step.run.startsWith('>') || step.run.startsWith('|'))) {
        throw new Error(`Step ${jobName}.${index} uses unsupported folded/chomping run scalar`);
      }
      
      if (step.run.includes('${{')) {
        throw new Error(`Step ${jobName}.${index} run script contains \${{`);
      }
      
      let stepEnv = { ...jobEnv, ...(step.env || {}) };
      for (const val of Object.values(stepEnv)) {
        if (val.includes('${{')) {
          throw new Error(`Step ${jobName}.${index} env value contains \${{`);
        }
      }
      
      steps.push({
        key: `${jobName}.${index}`,
        name: step.name || '',
        script: step.run,
        env: stepEnv,
        workingDirectory: step.workingDirectory
      });
    }
  }
  
  for (const localStep of LOCAL_STEPS) {
    steps.push({
      key: localStep.name,
      name: localStep.name,
      script: localStep.script,
      env: {},
      workingDirectory: undefined
    });
  }
  
  return steps;
}

export function localize(script) {
  const kept = [];
  const skipped = [];
  const LOCAL_SKIP = /^\s*(sudo\s|bash scripts\/ci-install-ubuntu-packages\.sh\b)/;
  
  for (const line of script.split('\n')) {
    if (LOCAL_SKIP.test(line)) {
      skipped.push(line.trim());
    } else {
      kept.push(line);
    }
  }
  
  return { script: kept.join('\n'), skipped };
}

async function main() {
  const usage = 'Usage: node scripts/run-ci-offline.mjs [--checkout <dir>] [--logs <dir>] [--list] [--only <substring>]';
  const args = process.argv.slice(2);
  let checkout = repositoryRoot;
  let logsDir = null;
  let list = false;
  let only = null;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--checkout') {
      if (i + 1 >= args.length) {
        process.stderr.write(usage + '\n');
        process.exit(2);
      }
      checkout = path.resolve(args[++i]);
    } else if (args[i] === '--logs') {
      if (i + 1 >= args.length) {
        process.stderr.write(usage + '\n');
        process.exit(2);
      }
      logsDir = path.resolve(args[++i]);
    } else if (args[i] === '--list') {
      list = true;
    } else if (args[i] === '--only') {
      if (i + 1 >= args.length) {
        process.stderr.write(usage + '\n');
        process.exit(2);
      }
      only = args[++i];
    } else {
      process.stderr.write(usage + '\n');
      process.exit(2);
    }
  }
  
  if (!logsDir) {
    logsDir = path.join(os.tmpdir(), 'northstar-ci-offline', path.basename(checkout));
  }
  
  const workflowPath = path.join(checkout, '.github/workflows/ci.yml');
  const workflowText = fs.readFileSync(workflowPath, 'utf8');
  const jobs = parseWorkflowJobs(workflowText);
  
  let steps = selectSteps(jobs);
  
  if (only) {
    steps = steps.filter(s => s.key.includes(only) || s.name.includes(only));
  }
  
  if (steps.length === 0) {
    process.stderr.write('Error: No steps selected\n');
    process.exit(2);
  }
  
  if (list) {
    for (const step of steps) {
      console.log(`${step.key}  ${step.name}`);
    }
    process.exit(0);
  }
  
  fs.mkdirSync(logsDir, { recursive: true });
  let failed = false;
  
  for (const step of steps) {
    const { script, skipped } = localize(step.script);
    for (const skipLine of skipped) {
      console.log(`LOCAL-SKIP ${step.key}: ${skipLine}`);
    }
    
    const runnerTemp = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-runner-temp-'));
    try {
      const fullEnv = { 
        ...process.env, 
        ...step.env, 
        RUNNER_TEMP: runnerTemp, 
        GITHUB_WORKSPACE: checkout, 
        CI: 'true' 
      };
      
      const cwd = step.workingDirectory ? path.join(checkout, step.workingDirectory) : checkout;
      const logFile = path.join(logsDir, `${step.key}.log`);
      
      const logFd = fs.openSync(logFile, 'w');
      const result = spawnSync('bash', ['--noprofile', '--norc', '-x', '-eo', 'pipefail', '-c', script], {
        cwd,
        env: fullEnv,
        stdio: ['ignore', logFd, logFd]
      });
      fs.closeSync(logFd);
      
      if (result.status === 0) {
        console.log(`PASS ${step.key} ${step.name}`);
      } else {
        console.log(`FAIL ${step.key} ${step.name} (log ${logFile})`);
        failed = true;
      }
    } finally {
      fs.rmSync(runnerTemp, { recursive: true, force: true });
    }
  }
  
  if (failed) {
    process.exit(1);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err => {
    process.stderr.write(err.message + '\n');
    process.exit(2);
  });
}
