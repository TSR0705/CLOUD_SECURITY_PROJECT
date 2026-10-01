import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, execSync } from 'node:child_process';
import type { SeverityLevel, ConfidenceLevel } from '@sug/shared';

export const YARA_ENGINE = 'yara-x' as const;
export const YARA_ENGINE_VERSION = '1.20.0' as const;
export const YARA_CHECK_ID = 'scanner.yara' as const;
export const DEFAULT_YARA_TIMEOUT_SECONDS = 30;

export type YaraScanStatus = 'CLEAN' | 'MATCH' | 'ERROR';

export interface YaraRuleMeta {
  description?: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  author?: string;
  [key: string]: unknown;
}

export interface YaraRuleMatch {
  identifier: string;
  meta: YaraRuleMeta;
  rawMeta?: [string, unknown][] | undefined;
}

export interface YaraScanResult {
  status: YaraScanStatus;
  engine: typeof YARA_ENGINE;
  engineVersion: typeof YARA_ENGINE_VERSION;
  signatureVersion: string;
  matches: YaraRuleMatch[];
  durationMs: number;
  rawOutput?: string | undefined;
  error?: string | null | undefined;
}

export interface YaraScannerConfig {
  binaryPath?: string | undefined;
  rulesPath?: string | undefined;
  timeoutSeconds?: number | undefined;
  signatureVersion?: string | undefined;
}

const VALID_SEVERITIES: Record<string, SeverityLevel> = {
  low: 'LOW',
  medium: 'MEDIUM',
  high: 'HIGH',
  critical: 'CRITICAL',
  info: 'INFO',
};

const VALID_CONFIDENCES: Record<string, ConfidenceLevel> = {
  low: 'LOW',
  medium: 'MEDIUM',
  high: 'HIGH',
  confirmed: 'CONFIRMED',
};

/**
 * Normalizes and validates the tuple metadata format emitted by YARA-X NDJSON.
 * In YARA-X 1.20.0, meta is serialized as: [["severity", "critical"], ["confidence", "high"], ...]
 *
 * Mandatory metadata:
 * - severity: low | medium | high | critical | info
 * - confidence: low | medium | high | confirmed
 *
 * Throws an Error if mandatory metadata is missing or invalid.
 */
export function parseAndValidateRuleMeta(metaTuples?: unknown): YaraRuleMeta {
  if (!Array.isArray(metaTuples)) {
    throw new Error('Missing or invalid rule metadata array');
  }

  const rawMap: Record<string, unknown> = {};
  for (const item of metaTuples) {
    if (Array.isArray(item) && item.length >= 2) {
      const key = String(item[0]).trim().toLowerCase();
      rawMap[key] = item[1];
    }
  }

  const rawSeverity = rawMap['severity'];
  if (typeof rawSeverity !== 'string' || !VALID_SEVERITIES[rawSeverity.toLowerCase()]) {
    throw new Error(
      `Invalid or missing mandatory metadata 'severity': '${String(rawSeverity)}'. Allowed: ${Object.keys(
        VALID_SEVERITIES,
      ).join(', ')}`,
    );
  }

  const rawConfidence = rawMap['confidence'];
  if (typeof rawConfidence !== 'string' || !VALID_CONFIDENCES[rawConfidence.toLowerCase()]) {
    throw new Error(
      `Invalid or missing mandatory metadata 'confidence': '${String(rawConfidence)}'. Allowed: ${Object.keys(
        VALID_CONFIDENCES,
      ).join(', ')}`,
    );
  }

  const meta: YaraRuleMeta = {
    severity: VALID_SEVERITIES[rawSeverity.toLowerCase()]!,
    confidence: VALID_CONFIDENCES[rawConfidence.toLowerCase()]!,
  };

  if (typeof rawMap['description'] === 'string') {
    meta.description = rawMap['description'];
  }
  if (typeof rawMap['author'] === 'string') {
    meta.author = rawMap['author'];
  }

  for (const [k, v] of Object.entries(rawMap)) {
    if (k !== 'severity' && k !== 'confidence' && k !== 'description' && k !== 'author') {
      meta[k] = v;
    }
  }

  return meta;
}

export interface YaraRulesProvenance {
  signatureVersion: string;
  rulesGitRevision: string | null;
  rulesContentSha256: string;
  source: 'env' | 'manifest' | 'git' | 'content_hash';
}

/**
 * Deterministically resolves the complete provenance (Git SHA, content SHA-256,
 * and authoritative signature_version) for the specified rules directory.
 */
export function resolveYaraProvenance(rulesPath: string): YaraRulesProvenance {
  const resolvedPath = path.resolve(rulesPath);
  const contentHash = computeRulesDirectoryContentHash(resolvedPath);

  // 1. Explicit environment variable override
  if (process.env.YARA_RULES_VERSION && process.env.YARA_RULES_VERSION.trim() !== '') {
    const envVal = process.env.YARA_RULES_VERSION.trim();
    return {
      signatureVersion: envVal,
      rulesGitRevision: envVal.length === 40 && /^[0-9a-f]{40}$/i.test(envVal) ? envVal : null,
      rulesContentSha256: contentHash,
      source: 'env',
    };
  }

  // 2. Check for build-time generated manifest (rules_manifest.json)
  const manifestFile = path.join(resolvedPath, 'rules_manifest.json');
  if (fs.existsSync(manifestFile)) {
    try {
      const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
      if (manifest && typeof manifest === 'object') {
        const manifestSigVer =
          typeof manifest.signatureVersion === 'string' && manifest.signatureVersion.trim()
            ? manifest.signatureVersion.trim()
            : typeof manifest.version === 'string' && manifest.version.trim()
              ? manifest.version.trim()
              : null;

        const manifestContentSha =
          typeof manifest.rulesContentSha256 === 'string' && manifest.rulesContentSha256.trim()
            ? manifest.rulesContentSha256.trim()
            : null;

        const manifestGitRev =
          typeof manifest.rulesGitRevision === 'string' && manifest.rulesGitRevision.trim()
            ? manifest.rulesGitRevision.trim()
            : null;

        if (manifestSigVer) {
          // If manifest content SHA matches current content hash, or if no manifestContentSha,
          // the rules are unmutated and exact.
          if (!manifestContentSha || manifestContentSha === contentHash) {
            return {
              signatureVersion: manifestSigVer,
              rulesGitRevision: manifestGitRev,
              rulesContentSha256: contentHash,
              source: 'manifest',
            };
          }
          // If content changed since manifest was generated, manifest is stale: fall through
        }
      }
    } catch {
      // fallback
    }
  }

  const dotVersionFile = path.join(resolvedPath, '.rules-version');
  if (fs.existsSync(dotVersionFile)) {
    try {
      const versionStr = fs.readFileSync(dotVersionFile, 'utf8').trim();
      if (versionStr) {
        return {
          signatureVersion: versionStr,
          rulesGitRevision:
            versionStr.length === 40 && /^[0-9a-f]{40}$/i.test(versionStr) ? versionStr : null,
          rulesContentSha256: contentHash,
          source: 'manifest',
        };
      }
    } catch {
      // fallback
    }
  }

  // 3. Try to get Git commit SHA of the rules directory if git repo is present
  try {
    const gitDir = path.join(process.cwd(), '.git');
    if (fs.existsSync(gitDir)) {
      const statusRes = execSync(`git status --porcelain -- "${resolvedPath}"`, {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      const dirtyRuleFiles = statusRes
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.endsWith('.yar') || l.endsWith('.yara'));
      const isClean = dirtyRuleFiles.length === 0;

      const gitSha = execSync(`git log -1 --format=%H -- "${resolvedPath}"`, {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();

      if (gitSha && gitSha.length === 40) {
        if (isClean) {
          // Clean working tree: signatureVersion is Git commit SHA
          return {
            signatureVersion: gitSha,
            rulesGitRevision: gitSha,
            rulesContentSha256: contentHash,
            source: 'git',
          };
        } else {
          // Modified working tree: rules have changed since commit, so version must reflect change
          return {
            signatureVersion: `${gitSha}-dirty-${contentHash.slice(0, 8)}`,
            rulesGitRevision: gitSha,
            rulesContentSha256: contentHash,
            source: 'git',
          };
        }
      }
    }
  } catch {
    // fallback if git is unavailable or rulesPath not committed yet
  }

  // 4. Deterministic content tree hash fallback (SHA-256 over all sorted rule contents)
  return {
    signatureVersion: contentHash,
    rulesGitRevision: null,
    rulesContentSha256: contentHash,
    source: 'content_hash',
  };
}

/**
 * Deterministically resolves the signature_version (Git SHA or deterministic tree hash)
 * for the specified rules directory.
 */
export function resolveYaraSignatureVersion(rulesPath: string): string {
  return resolveYaraProvenance(rulesPath).signatureVersion;
}

/**
 * Computes a deterministic SHA-256 hash across all .yar and .yara files in a directory.
 */
export function computeRulesDirectoryContentHash(dirPath: string): string {
  if (!fs.existsSync(dirPath)) {
    return '0000000000000000000000000000000000000000000000000000000000000000';
  }

  const stat = fs.statSync(dirPath);
  if (!stat.isDirectory()) {
    const content = fs.readFileSync(dirPath);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  const ruleFiles: { relPath: string; fullPath: string }[] = [];
  function walk(current: string) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && (entry.name.endsWith('.yar') || entry.name.endsWith('.yara'))) {
        ruleFiles.push({
          relPath: path.relative(dirPath, full).replace(/\\/g, '/'),
          fullPath: full,
        });
      }
    }
  }
  walk(dirPath);

  ruleFiles.sort((a, b) => a.relPath.localeCompare(b.relPath));

  const hash = crypto.createHash('sha256');
  for (const rf of ruleFiles) {
    hash.update(rf.relPath);
    hash.update('\0');
    const content = fs.readFileSync(rf.fullPath);
    hash.update(content);
    hash.update('\0');
  }

  return hash.digest('hex');
}

/**
 * Parses raw NDJSON output string from `yr scan --output-format ndjson`.
 * FAIL-CLOSED: Does not rely on exit code. Validates each JSON line and rule metadata.
 */
export function parseYaraNdjsonOutput(
  rawStdout: string,
  signatureVersion: string,
  durationMs: number,
): YaraScanResult {
  const lines = rawStdout.split(/\r?\n/).filter((l) => l.trim().length > 0);

  if (lines.length === 0) {
    // Empty output without rules or errors
    return {
      status: 'CLEAN',
      engine: YARA_ENGINE,
      engineVersion: YARA_ENGINE_VERSION,
      signatureVersion,
      matches: [],
      durationMs,
      rawOutput: rawStdout,
      error: null,
    };
  }

  const matches: YaraRuleMatch[] = [];

  for (const line of lines) {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(line);
    } catch {
      return {
        status: 'ERROR',
        engine: YARA_ENGINE,
        engineVersion: YARA_ENGINE_VERSION,
        signatureVersion,
        matches: [],
        durationMs,
        rawOutput: rawStdout,
        error: `Malformed NDJSON line emitted by YARA-X: ${line}`,
      };
    }

    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.rules)) {
      return {
        status: 'ERROR',
        engine: YARA_ENGINE,
        engineVersion: YARA_ENGINE_VERSION,
        signatureVersion,
        matches: [],
        durationMs,
        rawOutput: rawStdout,
        error: `Unexpected NDJSON schema emitted by YARA-X: missing 'rules' array`,
      };
    }

    for (const rule of parsed.rules as Record<string, unknown>[]) {
      if (!rule || typeof rule.identifier !== 'string') {
        return {
          status: 'ERROR',
          engine: YARA_ENGINE,
          engineVersion: YARA_ENGINE_VERSION,
          signatureVersion,
          matches: [],
          durationMs,
          rawOutput: rawStdout,
          error: `Malformed rule match object: missing 'identifier'`,
        };
      }

      try {
        const meta = parseAndValidateRuleMeta(rule.meta);
        matches.push({
          identifier: rule.identifier,
          meta,
          rawMeta: Array.isArray(rule.meta) ? (rule.meta as [string, unknown][]) : undefined,
        });
      } catch (metaErr) {
        return {
          status: 'ERROR',
          engine: YARA_ENGINE,
          engineVersion: YARA_ENGINE_VERSION,
          signatureVersion,
          matches: [],
          durationMs,
          rawOutput: rawStdout,
          error: `Rule '${rule.identifier}' has invalid metadata: ${(metaErr as Error).message}`,
        };
      }
    }
  }

  const status: YaraScanStatus = matches.length > 0 ? 'MATCH' : 'CLEAN';

  return {
    status,
    engine: YARA_ENGINE,
    engineVersion: YARA_ENGINE_VERSION,
    signatureVersion,
    matches,
    durationMs,
    rawOutput: rawStdout,
    error: null,
  };
}

/**
 * YARA-X 1.20.0 Scanner Client
 * Executes `yr scan --output-format ndjson --timeout 30 --print-meta <rulesPath> <filePath>`
 * using safe child process spawn with strict fail-closed error handling.
 */
export class YaraScanner {
  readonly binaryPath: string;
  readonly rulesPath: string;
  readonly timeoutSeconds: number;
  private cachedSignatureVersion?: string;

  constructor(config?: YaraScannerConfig) {
    this.binaryPath = config?.binaryPath ?? process.env.YARA_BINARY_PATH ?? 'yr';
    this.rulesPath =
      config?.rulesPath ??
      process.env.YARA_RULES_PATH ??
      path.resolve(process.cwd(), 'packages/scanner/rules');
    this.timeoutSeconds = config?.timeoutSeconds ?? DEFAULT_YARA_TIMEOUT_SECONDS;
    if (config?.signatureVersion) {
      this.cachedSignatureVersion = config.signatureVersion;
    }
  }

  /**
   * Returns the signature_version Git SHA / hash for the configured rules.
   */
  getSignatureVersion(): string {
    if (!this.cachedSignatureVersion) {
      this.cachedSignatureVersion = resolveYaraSignatureVersion(this.rulesPath);
    }
    return this.cachedSignatureVersion;
  }

  /**
   * Verifies that the YARA-X binary is executable and returns version 1.20.0.
   */
  async ping(): Promise<boolean> {
    try {
      const res = await this.execCommand(['--version']);
      return res.stdout.includes('1.20.0') || res.stdout.includes('yara-x');
    } catch {
      return false;
    }
  }

  /**
   * Scans a staged artifact file with YARA-X 1.20.0 using canonical invocation:
   * yr scan --output-format ndjson --timeout 30 --print-meta <rulesPath> <filePath>
   */
  async scanFile(filePath: string, customRulesPath?: string): Promise<YaraScanResult> {
    const startTime = Date.now();
    const effectiveRulesPath = customRulesPath ?? this.rulesPath;
    const signatureVersion = customRulesPath
      ? resolveYaraSignatureVersion(customRulesPath)
      : this.getSignatureVersion();

    // Verify target file exists
    if (!fs.existsSync(filePath)) {
      return {
        status: 'ERROR',
        engine: YARA_ENGINE,
        engineVersion: YARA_ENGINE_VERSION,
        signatureVersion,
        matches: [],
        durationMs: Date.now() - startTime,
        error: `Target artifact file does not exist: ${filePath}`,
      };
    }

    // Verify rules path exists
    if (!fs.existsSync(effectiveRulesPath)) {
      return {
        status: 'ERROR',
        engine: YARA_ENGINE,
        engineVersion: YARA_ENGINE_VERSION,
        signatureVersion,
        matches: [],
        durationMs: Date.now() - startTime,
        error: `YARA-X rules path does not exist: ${effectiveRulesPath}`,
      };
    }

    // Canonical invocation:
    // yr scan --output-format ndjson --timeout 30 --print-meta rules/ <file>
    const args = [
      'scan',
      '--output-format',
      'ndjson',
      '--timeout',
      String(this.timeoutSeconds),
      '--print-meta',
      effectiveRulesPath,
      filePath,
    ];

    try {
      const execResult = await this.execCommand(args, (this.timeoutSeconds + 5) * 1000);
      const durationMs = Date.now() - startTime;

      // Fail-closed on non-zero exit code (syntax error, compile error, CLI failure)
      if (execResult.exitCode !== 0) {
        return {
          status: 'ERROR',
          engine: YARA_ENGINE,
          engineVersion: YARA_ENGINE_VERSION,
          signatureVersion,
          matches: [],
          durationMs,
          rawOutput: execResult.stdout,
          error: `YARA-X exited with non-zero code ${execResult.exitCode}: ${
            execResult.stderr.trim() || execResult.stdout.trim()
          }`,
        };
      }

      return parseYaraNdjsonOutput(execResult.stdout, signatureVersion, durationMs);
    } catch (procErr: unknown) {
      const durationMs = Date.now() - startTime;
      return {
        status: 'ERROR',
        engine: YARA_ENGINE,
        engineVersion: YARA_ENGINE_VERSION,
        signatureVersion,
        matches: [],
        durationMs,
        error: (procErr as Error)?.message || 'YARA-X execution failed',
      };
    }
  }

  private execCommand(
    args: string[],
    timeoutMs: number = 35_000,
  ): Promise<{ exitCode: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      let child: ReturnType<typeof spawn>;
      try {
        child = spawn(this.binaryPath, args, {
          stdio: ['ignore', 'pipe', 'pipe'],
          shell: false,
          windowsHide: true,
        });
      } catch (spawnErr) {
        return reject(
          new Error(
            `Failed to spawn YARA-X binary '${this.binaryPath}': ${(spawnErr as Error).message}`,
          ),
        );
      }

      let stdout = '';
      let stderr = '';
      let isTimedOut = false;

      const timer = setTimeout(() => {
        isTimedOut = true;
        child.kill('SIGKILL');
        reject(new Error(`YARA-X scan timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      if (child.stdout) {
        child.stdout.on('data', (chunk: Buffer) => {
          stdout += chunk.toString('utf8');
        });
      }

      if (child.stderr) {
        child.stderr.on('data', (chunk: Buffer) => {
          stderr += chunk.toString('utf8');
        });
      }

      child.on('error', (err) => {
        clearTimeout(timer);
        if (!isTimedOut) {
          reject(new Error(`YARA-X process error (${this.binaryPath}): ${err.message}`));
        }
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        if (!isTimedOut) {
          resolve({ exitCode: code, stdout, stderr });
        }
      });
    });
  }
}
