#!/usr/bin/env node
import fs from 'node:fs';

const args = process.argv.slice(2);
if (args.includes('--version')) {
  process.stdout.write('qpdf version 11.3.0 (test mock)\n');
  process.exit(0);
}

const mode = process.env.MOCK_QPDF_MODE || 'success';
const outputPath = args[args.length - 1];
const inputPath = args[args.length - 2];

if (mode === 'timeout') {
  // Sleep 15 seconds to trigger timeout
  await new Promise((resolve) => setTimeout(resolve, 15000));
  process.exit(0);
}

if (mode === 'malformed') {
  process.stderr.write('WARNING: file is damaged\nqpdf: unable to find trailer dictionary\n');
  process.exit(2);
}

if (mode === 'error') {
  process.stderr.write('qpdf internal error: memory allocation failure\n');
  process.exit(1);
}

if (mode === 'warnings') {
  const content = fs.readFileSync(inputPath);
  fs.writeFileSync(outputPath, content);
  process.stderr.write('WARNING: recovered damaged xref\n');
  process.exit(3);
}

// default: success
const content = fs.readFileSync(inputPath);
fs.writeFileSync(outputPath, content);
process.exit(0);
