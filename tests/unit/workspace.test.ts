import { describe, it, expect } from 'vitest';
import { SharedPackageName, SharedInfo } from '../../packages/shared/src/index.js';

describe('Monorepo Workspace Contract Test', () => {
  it('should expose the correct package identity for @sug/shared', () => {
    expect(SharedPackageName).toBe('@sug/shared');
    expect(SharedInfo.name).toBe('@sug/shared');
    expect(SharedInfo.version).toBe('0.1.0');
  });

  it('should conform to semantic versioning', () => {
    const semverRegex = /^\d+\.\d+\.\d+$/;
    expect(SharedInfo.version).toMatch(semverRegex);
  });
});
