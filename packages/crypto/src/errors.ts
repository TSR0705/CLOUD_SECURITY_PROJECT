/**
 * @sug/crypto/errors
 * Typed error hierarchy for cryptographic operations and envelope parsing.
 */

export class CryptoError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'CryptoError';
  }
}

export class InvalidMagicError extends CryptoError {
  constructor(actualMagic: string) {
    super(`Invalid envelope magic: expected 'SUG1', got '${actualMagic}'`);
    this.name = 'InvalidMagicError';
  }
}

export class UnsupportedVersionError extends CryptoError {
  constructor(actualVersion: number) {
    super(`Unsupported SUG1 envelope version: expected 1, got ${actualVersion}`);
    this.name = 'UnsupportedVersionError';
  }
}

export class InvalidEnvelopeError extends CryptoError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidEnvelopeError';
  }
}

export class AuthenticationError extends CryptoError {
  constructor(
    message = 'Ciphertext authentication failed: tag mismatch, altered AAD, or corrupted payload',
  ) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class KeyProviderError extends CryptoError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'KeyProviderError';
  }
}

export class InvalidAadError extends CryptoError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidAadError';
  }
}
