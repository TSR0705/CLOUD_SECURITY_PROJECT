import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {
  YARA_ENGINE,
  YARA_ENGINE_VERSION,
  YARA_CHECK_ID,
  YaraScanner,
  parseAndValidateRuleMeta,
  parseYaraNdjsonOutput,
  computeRulesDirectoryContentHash,
  resolveYaraSignatureVersion,
  resolveYaraProvenance,
} from '../../../packages/scanner/src/yara.js';

describe('Phase P15: YARA-X Unit Test Suite', () => {
  // ============================================================
  // 1. Version Pinning and Constants
  // ============================================================
  describe('Constants and Engine Version', () => {
    it('pins engine identifier and version 1.20.0 explicitly', () => {
      expect(YARA_ENGINE).toBe('yara-x');
      expect(YARA_ENGINE_VERSION).toBe('1.20.0');
      expect(YARA_CHECK_ID).toBe('scanner.yara');
    });
  });

  // ============================================================
  // 2. Metadata Parser & Validator
  // ============================================================
  describe('parseAndValidateRuleMeta', () => {
    it('parses valid severity and confidence tuples', () => {
      const tuples: [string, unknown][] = [
        ['description', 'A test signature'],
        ['severity', 'critical'],
        ['confidence', 'high'],
        ['author', 'SecOps'],
        ['custom_tag', 12345],
      ];

      const meta = parseAndValidateRuleMeta(tuples);
      expect(meta.severity).toBe('CRITICAL');
      expect(meta.confidence).toBe('HIGH');
      expect(meta.description).toBe('A test signature');
      expect(meta.author).toBe('SecOps');
      expect(meta['custom_tag']).toBe(12345);
    });

    it('accepts all canonical severity levels', () => {
      for (const sev of ['low', 'medium', 'high', 'critical', 'info']) {
        const meta = parseAndValidateRuleMeta([
          ['severity', sev],
          ['confidence', 'high'],
        ]);
        expect(meta.severity).toBe(sev.toUpperCase());
      }
    });

    it('accepts all canonical confidence levels', () => {
      for (const conf of ['low', 'medium', 'high', 'confirmed']) {
        const meta = parseAndValidateRuleMeta([
          ['severity', 'high'],
          ['confidence', conf],
        ]);
        expect(meta.confidence).toBe(conf.toUpperCase());
      }
    });

    it('fails closed when severity is missing', () => {
      expect(() =>
        parseAndValidateRuleMeta([
          ['confidence', 'high'],
          ['description', 'missing severity'],
        ]),
      ).toThrow(/missing mandatory metadata 'severity'/i);
    });

    it('fails closed when severity is invalid', () => {
      expect(() =>
        parseAndValidateRuleMeta([
          ['severity', 'super-critical-custom'],
          ['confidence', 'high'],
        ]),
      ).toThrow(/invalid or missing mandatory metadata 'severity'/i);
    });

    it('fails closed when confidence is missing', () => {
      expect(() =>
        parseAndValidateRuleMeta([
          ['severity', 'critical'],
          ['description', 'missing confidence'],
        ]),
      ).toThrow(/missing mandatory metadata 'confidence'/i);
    });

    it('fails closed when confidence is invalid', () => {
      expect(() =>
        parseAndValidateRuleMeta([
          ['severity', 'critical'],
          ['confidence', 'absolute-certainty'],
        ]),
      ).toThrow(/invalid or missing mandatory metadata 'confidence'/i);
    });

    it('fails closed on non-array input', () => {
      expect(() => parseAndValidateRuleMeta(null)).toThrow(/invalid rule metadata array/i);
      expect(() => parseAndValidateRuleMeta('invalid')).toThrow(/invalid rule metadata array/i);
    });
  });

  // ============================================================
  // 3. NDJSON Stream Parser
  // ============================================================
  describe('parseYaraNdjsonOutput', () => {
    const sigVer = 'a1b2c3d4e5f678901234567890abcdef12345678';

    it('parses empty / clean scan output as CLEAN with 0 matches', () => {
      const cleanNdjson = '{"path":"/tmp/clean.bin","rules":[]}\n';
      const result = parseYaraNdjsonOutput(cleanNdjson, sigVer, 15);

      expect(result.status).toBe('CLEAN');
      expect(result.matches).toHaveLength(0);
      expect(result.engine).toBe('yara-x');
      expect(result.engineVersion).toBe('1.20.0');
      expect(result.signatureVersion).toBe(sigVer);
      expect(result.durationMs).toBe(15);
      expect(result.error).toBeNull();
    });

    it('parses single rule match into typed findings', () => {
      const matchNdjson = JSON.stringify({
        path: '/tmp/test.bin',
        rules: [
          {
            identifier: 'P15_Test_Malware_Signature',
            meta: [
              ['description', 'Canonical P15 test malware pattern for scan-03'],
              ['severity', 'critical'],
              ['confidence', 'high'],
            ],
          },
        ],
      });

      const result = parseYaraNdjsonOutput(matchNdjson, sigVer, 25);

      expect(result.status).toBe('MATCH');
      expect(result.matches).toHaveLength(1);
      expect(result.matches[0].identifier).toBe('P15_Test_Malware_Signature');
      expect(result.matches[0].meta.severity).toBe('CRITICAL');
      expect(result.matches[0].meta.confidence).toBe('HIGH');
      expect(result.matches[0].meta.description).toBe(
        'Canonical P15 test malware pattern for scan-03',
      );
      expect(result.error).toBeNull();
    });

    it('preserves ALL findings when multiple rules match without dropping any', () => {
      const multiNdjson = JSON.stringify({
        path: '/tmp/multi.bin',
        rules: [
          {
            identifier: 'ThreatRule_Primary',
            meta: [
              ['severity', 'critical'],
              ['confidence', 'high'],
              ['description', 'Primary rule'],
            ],
          },
          {
            identifier: 'ThreatRule_Secondary',
            meta: [
              ['severity', 'high'],
              ['confidence', 'medium'],
              ['description', 'Secondary rule'],
            ],
          },
          {
            identifier: 'ThreatRule_Heuristic',
            meta: [
              ['severity', 'low'],
              ['confidence', 'low'],
              ['description', 'Heuristic observation'],
            ],
          },
        ],
      });

      const result = parseYaraNdjsonOutput(multiNdjson, sigVer, 30);

      expect(result.status).toBe('MATCH');
      expect(result.matches).toHaveLength(3);
      expect(result.matches.map((m) => m.identifier)).toEqual([
        'ThreatRule_Primary',
        'ThreatRule_Secondary',
        'ThreatRule_Heuristic',
      ]);
      expect(result.matches[0].meta.severity).toBe('CRITICAL');
      expect(result.matches[1].meta.severity).toBe('HIGH');
      expect(result.matches[2].meta.severity).toBe('LOW');
    });

    it('fails closed with ERROR on malformed JSON line', () => {
      const malformed = '{"path":"/tmp/test.bin", rules: broken json\n';
      const result = parseYaraNdjsonOutput(malformed, sigVer, 10);

      expect(result.status).toBe('ERROR');
      expect(result.matches).toHaveLength(0);
      expect(result.error).toMatch(/Malformed NDJSON line/i);
    });

    it('fails closed with ERROR on unexpected JSON schema (missing rules array)', () => {
      const badSchema = JSON.stringify({ path: '/tmp/test.bin', notRules: [] });
      const result = parseYaraNdjsonOutput(badSchema, sigVer, 10);

      expect(result.status).toBe('ERROR');
      expect(result.error).toMatch(/missing 'rules' array/i);
    });

    it('fails closed with ERROR when matched rule contains invalid metadata', () => {
      const invalidMetaNdjson = JSON.stringify({
        path: '/tmp/test.bin',
        rules: [
          {
            identifier: 'InvalidMetaRule',
            meta: [['severity', 'INVALID_SEV']], // missing confidence & invalid severity
          },
        ],
      });

      const result = parseYaraNdjsonOutput(invalidMetaNdjson, sigVer, 12);

      expect(result.status).toBe('ERROR');
      expect(result.error).toMatch(/invalid metadata/i);
    });
  });

  // ============================================================
  // 4. Signature Version Provenance & Content Hashing
  // ============================================================
  describe('Signature Version Derivation & Provenance', () => {
    let tempRulesDir: string;

    it('computes deterministic content tree hash across sorted rule files', () => {
      tempRulesDir = path.join(os.tmpdir(), `sug-yara-hash-test-${crypto.randomUUID()}`);
      fs.mkdirSync(tempRulesDir, { recursive: true });

      fs.writeFileSync(
        path.join(tempRulesDir, 'b_rule.yar'),
        'rule RuleB { meta: severity = "low" confidence = "low" condition: true }',
      );
      fs.writeFileSync(
        path.join(tempRulesDir, 'a_rule.yar'),
        'rule RuleA { meta: severity = "high" confidence = "high" condition: true }',
      );

      const hash1 = computeRulesDirectoryContentHash(tempRulesDir);
      const hash2 = computeRulesDirectoryContentHash(tempRulesDir);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64);

      // Mutating a rule changes the signature version hash
      fs.appendFileSync(path.join(tempRulesDir, 'a_rule.yar'), '\n// comment');
      const hash3 = computeRulesDirectoryContentHash(tempRulesDir);
      expect(hash3).not.toBe(hash1);

      fs.rmSync(tempRulesDir, { recursive: true, force: true });
    });

    it('guarantees same rules = same version, and changed rules = different version', () => {
      tempRulesDir = path.join(os.tmpdir(), `sug-yara-version-diff-${crypto.randomUUID()}`);
      fs.mkdirSync(tempRulesDir, { recursive: true });

      fs.writeFileSync(
        path.join(tempRulesDir, 'rule1.yar'),
        'rule Rule1 { meta: severity = "medium" confidence = "medium" condition: true }',
      );

      const ver1 = resolveYaraSignatureVersion(tempRulesDir);
      const ver2 = resolveYaraSignatureVersion(tempRulesDir);
      expect(ver1).toBe(ver2);

      // Mutating rule content produces a different version
      fs.writeFileSync(
        path.join(tempRulesDir, 'rule1.yar'),
        'rule Rule1 { meta: severity = "high" confidence = "high" condition: true }',
      );

      const ver3 = resolveYaraSignatureVersion(tempRulesDir);
      expect(ver3).not.toBe(ver1);

      fs.rmSync(tempRulesDir, { recursive: true, force: true });
    });

    it('resolves signature version from rules_manifest.json in container environments without .git', () => {
      tempRulesDir = path.join(os.tmpdir(), `sug-yara-manifest-test-${crypto.randomUUID()}`);
      fs.mkdirSync(tempRulesDir, { recursive: true });

      const ruleFile = path.join(tempRulesDir, 'manifested.yar');
      fs.writeFileSync(
        ruleFile,
        'rule ManifestedRule { meta: severity = "high" confidence = "high" condition: true }',
      );
      const contentSha = computeRulesDirectoryContentHash(tempRulesDir);

      const bakedGitRevision = '262ebdac9c92cc61e1ce0b1c978793ae0267534f';
      fs.writeFileSync(
        path.join(tempRulesDir, 'rules_manifest.json'),
        JSON.stringify({
          signatureVersion: bakedGitRevision,
          rulesGitRevision: bakedGitRevision,
          rulesContentSha256: contentSha,
          generatedAt: new Date().toISOString(),
        }),
      );

      // Verify resolution in a standalone directory where no .git exists
      const provenance = resolveYaraProvenance(tempRulesDir);
      expect(provenance.source).toBe('manifest');
      expect(provenance.signatureVersion).toBe(bakedGitRevision);
      expect(provenance.rulesGitRevision).toBe(bakedGitRevision);
      expect(provenance.rulesContentSha256).toBe(contentSha);

      const version = resolveYaraSignatureVersion(tempRulesDir);
      expect(version).toBe(bakedGitRevision);

      fs.rmSync(tempRulesDir, { recursive: true, force: true });
    });

    it('detects altered rule content when manifest is stale and produces updated content hash', () => {
      tempRulesDir = path.join(os.tmpdir(), `sug-yara-stale-manifest-${crypto.randomUUID()}`);
      fs.mkdirSync(tempRulesDir, { recursive: true });

      fs.writeFileSync(
        path.join(tempRulesDir, 'rule.yar'),
        'rule RuleOriginal { meta: severity = "low" confidence = "low" condition: true }',
      );

      // Write manifest with old content hash
      fs.writeFileSync(
        path.join(tempRulesDir, 'rules_manifest.json'),
        JSON.stringify({
          signatureVersion: 'old_git_sha_1234567890abcdef1234567890abcdef12345678',
          rulesGitRevision: 'old_git_sha_1234567890abcdef1234567890abcdef12345678',
          rulesContentSha256:
            'stale_hash_0000000000000000000000000000000000000000000000000000000000000000',
        }),
      );

      const provenance = resolveYaraProvenance(tempRulesDir);
      // Because content changed from the stale manifest, it does NOT return the stale git revision
      expect(provenance.signatureVersion).not.toBe(
        'old_git_sha_1234567890abcdef1234567890abcdef12345678',
      );
      expect(provenance.rulesContentSha256).toBe(computeRulesDirectoryContentHash(tempRulesDir));

      fs.rmSync(tempRulesDir, { recursive: true, force: true });
    });
  });

  // ============================================================
  // 5. Fail-Closed Error Handling & Scanner Client
  // ============================================================
  describe('Fail-Closed Scanner Client Error Handling', () => {
    it('fails closed when binary is missing / non-existent', async () => {
      const nonExistentScanner = new YaraScanner({
        binaryPath: 'non_existent_yara_binary_xyz_123',
        rulesPath: 'packages/scanner/rules',
      });

      const tempFile = path.join(os.tmpdir(), `sug-test-${crypto.randomUUID()}.txt`);
      fs.writeFileSync(tempFile, 'test data');

      try {
        const result = await nonExistentScanner.scanFile(tempFile);
        expect(result.status).toBe('ERROR');
        expect(result.error).toBeDefined();
        expect(result.status).not.toBe('CLEAN');
      } finally {
        fs.unlinkSync(tempFile);
      }
    });

    it('fails closed when target file does not exist', async () => {
      const scanner = new YaraScanner({
        rulesPath: 'packages/scanner/rules',
      });

      const missingFile = path.join(os.tmpdir(), `sug-non-existent-${crypto.randomUUID()}.bin`);
      const result = await scanner.scanFile(missingFile);

      expect(result.status).toBe('ERROR');
      expect(result.error).toMatch(/target artifact file does not exist/i);
    });

    it('fails closed when rules directory does not exist', async () => {
      const scanner = new YaraScanner({
        rulesPath: 'packages/scanner/rules',
      });

      const tempFile = path.join(os.tmpdir(), `sug-test-${crypto.randomUUID()}.txt`);
      fs.writeFileSync(tempFile, 'test');

      try {
        const result = await scanner.scanFile(tempFile, 'non_existent_rules_dir_path_abcdef');
        expect(result.status).toBe('ERROR');
        expect(result.error).toMatch(/rules path does not exist/i);
      } finally {
        fs.unlinkSync(tempFile);
      }
    });
  });
});
