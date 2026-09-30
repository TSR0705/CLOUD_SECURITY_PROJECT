#!/usr/bin/env node

/**
 * YARA-X Rules Validation Gate (Build & Pre-commit Quality Gate)
 *
 * Validates that all YARA rules in a target directory:
 * 1. Compile successfully using the pinned YARA-X `yr` compiler.
 * 2. Contain mandatory metadata:
 *    - severity: 'low' | 'medium' | 'high' | 'critical' | 'info'
 *    - confidence: 'low' | 'medium' | 'high' | 'confirmed'
 *
 * Exits with code 0 on success.
 * Exits with non-zero code on compilation failure or metadata violation.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const ALLOWED_SEVERITY = new Set(['low', 'medium', 'high', 'critical', 'info']);
const ALLOWED_CONFIDENCE = new Set(['low', 'medium', 'high', 'confirmed']);

export function validateRulesDirectory(targetDir) {
  const resolvedDir = path.resolve(process.cwd(), targetDir);
  if (!fs.existsSync(resolvedDir)) {
    throw new Error(`Rules path does not exist: ${resolvedDir}`);
  }

  // 1. Run yr compile against the target directory/file
  const tempOutputFile = path.join(
    os.tmpdir(),
    `sug-yara-val-${crypto.randomUUID().slice(0, 8)}.yarc`,
  );

  try {
    const compileRes = spawnSync('yr', ['compile', resolvedDir, '-o', tempOutputFile], {
      encoding: 'utf8',
    });

    if (compileRes.error) {
      throw new Error(`Failed to execute yr compile: ${compileRes.error.message}`);
    }

    if (compileRes.status !== 0) {
      const errMsg = (compileRes.stderr || compileRes.stdout || '').trim();
      throw new Error(`YARA-X compilation failed (exit code ${compileRes.status}):\n${errMsg}`);
    }

    // 2. Inspect rules metadata by scanning a dummy buffer using yr scan
    const tempTarget = path.join(
      os.tmpdir(),
      `sug-dummy-target-${crypto.randomUUID().slice(0, 8)}.bin`,
    );
    try {
      fs.writeFileSync(tempTarget, Buffer.alloc(0));
      // Scan to trigger metadata enumeration or parse source files directly
      // Inspect source files directly for mandatory metadata
      validateRulesSourceFiles(resolvedDir);
    } finally {
      try {
        fs.unlinkSync(tempTarget);
      } catch {
        // ignore
      }
    }

    return { success: true, path: resolvedDir };
  } finally {
    try {
      if (fs.existsSync(tempOutputFile)) {
        fs.unlinkSync(tempOutputFile);
      }
    } catch {
      // ignore
    }
  }
}

function findRuleFiles(dir) {
  const stat = fs.statSync(dir);
  if (!stat.isDirectory()) {
    return [dir];
  }

  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...findRuleFiles(full));
    } else if (entry.isFile() && (entry.name.endsWith('.yar') || entry.name.endsWith('.yara'))) {
      files.push(full);
    }
  }
  return files;
}

function validateRulesSourceFiles(targetDir) {
  const files = findRuleFiles(targetDir);
  if (files.length === 0) {
    return;
  }

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');

    // Simple rule parser to check for metadata blocks
    const ruleRegex = /rule\s+([A-Za-z0-9_]+)\s*\{([^}]+)\}/gs;
    let match;
    while ((match = ruleRegex.exec(content)) !== null) {
      const ruleName = match[1];
      const ruleBody = match[2];

      const metaMatch = /meta\s*:\s*([^:]+?)(?=strings\s*:|condition\s*:|$)/s.exec(ruleBody);
      if (!metaMatch) {
        throw new Error(
          `Rule '${ruleName}' in ${file} is missing mandatory 'meta:' section with severity and confidence`,
        );
      }

      const metaContent = metaMatch[1];
      const severityMatch = /severity\s*=\s*"([^"]+)"/i.exec(metaContent);
      const confidenceMatch = /confidence\s*=\s*"([^"]+)"/i.exec(metaContent);

      if (!severityMatch) {
        throw new Error(`Rule '${ruleName}' in ${file} is missing mandatory 'severity' in meta`);
      }
      if (!confidenceMatch) {
        throw new Error(`Rule '${ruleName}' in ${file} is missing mandatory 'confidence' in meta`);
      }

      const severity = severityMatch[1].toLowerCase();
      const confidence = confidenceMatch[1].toLowerCase();

      if (!ALLOWED_SEVERITY.has(severity)) {
        throw new Error(
          `Rule '${ruleName}' in ${file} has invalid severity '${severity}'. Allowed: ${Array.from(ALLOWED_SEVERITY).join(', ')}`,
        );
      }

      if (!ALLOWED_CONFIDENCE.has(confidence)) {
        throw new Error(
          `Rule '${ruleName}' in ${file} has invalid confidence '${confidence}'. Allowed: ${Array.from(ALLOWED_CONFIDENCE).join(', ')}`,
        );
      }
    }
  }
}

// CLI entry point
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  const target = process.argv[2] || 'packages/scanner/rules';
  try {
    validateRulesDirectory(target);
    console.log(`[OK] All YARA-X rules in '${target}' compiled and passed metadata validation.`);
    process.exit(0);
  } catch (err) {
    console.error(`[ERROR] YARA-X Rule Validation Failed: ${err.message}`);
    process.exit(1);
  }
}
