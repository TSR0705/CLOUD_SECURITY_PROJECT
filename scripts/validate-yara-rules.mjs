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

export function computeRulesContentSha256(targetDir) {
  const resolvedDir = path.resolve(process.cwd(), targetDir);
  const files = findRuleFiles(resolvedDir);
  files.sort();

  const hash = crypto.createHash('sha256');
  for (const f of files) {
    const rel = path.relative(resolvedDir, f).replace(/\\/g, '/');
    hash.update(rel);
    hash.update('\0');
    hash.update(fs.readFileSync(f));
    hash.update('\0');
  }
  return hash.digest('hex');
}

export function generateRulesManifest(targetDir) {
  const resolvedDir = path.resolve(process.cwd(), targetDir);
  const contentSha256 = computeRulesContentSha256(resolvedDir);

  let gitRevision = null;
  let isClean = false;

  try {
    const gitDir = path.join(process.cwd(), '.git');
    if (fs.existsSync(gitDir)) {
      const status = spawnSync('git', ['status', '--porcelain', '--', resolvedDir], {
        encoding: 'utf8',
      });
      const dirtyRuleFiles = (status.stdout || '')
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.endsWith('.yar') || l.endsWith('.yara'));
      isClean = status.status === 0 && dirtyRuleFiles.length === 0;

      const logRes = spawnSync('git', ['log', '-1', '--format=%H', '--', resolvedDir], {
        encoding: 'utf8',
      });
      if (logRes.status === 0 && logRes.stdout) {
        const sha = logRes.stdout.trim();
        if (sha.length === 40) {
          gitRevision = sha;
        }
      }
    }
  } catch {
    // git inspection optional
  }

  // If clean git revision is available, signatureVersion is Git SHA; otherwise content SHA
  const signatureVersion = gitRevision && isClean ? gitRevision : contentSha256;

  const manifest = {
    signatureVersion,
    rulesGitRevision: gitRevision,
    rulesContentSha256: contentSha256,
    generatedAt: new Date().toISOString(),
  };

  const manifestPath = path.join(resolvedDir, 'rules_manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
  return manifest;
}

export function validateRulesDirectory(targetDir, options = { generateManifest: true }) {
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

    // 2. Inspect source files directly for mandatory metadata
    validateRulesSourceFiles(resolvedDir);

    // 3. Generate or update build-time rules_manifest.json if requested
    let manifest = null;
    if (options.generateManifest) {
      manifest = generateRulesManifest(resolvedDir);
    }

    return { success: true, path: resolvedDir, manifest };
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
  const args = process.argv.slice(2);
  const noManifest = args.includes('--no-manifest');
  const target = args.find((a) => !a.startsWith('--')) || 'packages/scanner/rules';

  try {
    const res = validateRulesDirectory(target, { generateManifest: !noManifest });
    console.log(
      `[OK] All YARA-X rules in '${target}' compiled and passed metadata validation.${
        res.manifest ? ` Manifest generated (version: ${res.manifest.signatureVersion}).` : ''
      }`,
    );
    process.exit(0);
  } catch (err) {
    console.error(`[ERROR] YARA-X Rule Validation Failed: ${err.message}`);
    process.exit(1);
  }
}
