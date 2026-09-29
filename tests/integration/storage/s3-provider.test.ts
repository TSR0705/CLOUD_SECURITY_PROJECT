import { describe, it, expect, beforeAll } from 'vitest';
import {
  S3Client,
  HeadBucketCommand,
  CreateBucketCommand,
  PutBucketVersioningCommand,
} from '@aws-sdk/client-s3';
import {
  createS3Provider,
  buildQuarantineKey,
  AlreadyExists,
  VersionMissing,
  InvalidRequest,
  type StorageProvider,
} from '@sug/storage';
import { createHash, randomUUID } from 'node:crypto';

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
const S3_QUARANTINE_BUCKET = 'sug-quarantine-local';

describe('S3Provider Integration & P2 Spike Routing (LocalStack)', () => {
  let provider: StorageProvider;
  let rawS3: S3Client;

  beforeAll(async () => {
    rawS3 = new S3Client({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'test',
        secretAccessKey: 'test',
      },
      forcePathStyle: true,
    });

    // Ensure bucket exists with versioning enabled
    let s3Ready = false;
    for (let attempt = 0; attempt < 15; attempt++) {
      try {
        try {
          await rawS3.send(new HeadBucketCommand({ Bucket: S3_QUARANTINE_BUCKET }));
        } catch {
          await rawS3.send(new CreateBucketCommand({ Bucket: S3_QUARANTINE_BUCKET }));
        }
        await rawS3.send(
          new PutBucketVersioningCommand({
            Bucket: S3_QUARANTINE_BUCKET,
            VersioningConfiguration: { Status: 'Enabled' },
          }),
        );
        s3Ready = true;
        break;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    if (!s3Ready) {
      throw new Error(`Could not connect to LocalStack S3 emulator at ${S3_ENDPOINT}`);
    }

    // Initialize provider under test
    provider = createS3Provider({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'test',
        secretAccessKey: 'test',
      },
      forcePathStyle: true,
    });
  });

  // TEST P9-01 (Routing S3-01 through S3Provider): VERSIONED PUT
  it('P9-01: putIfAbsent returns valid non-empty VersionId on versioned bucket', async () => {
    const appId = randomUUID();
    const uploadId = randomUUID();
    const key = buildQuarantineKey(appId, uploadId);
    const content = Buffer.from('hello quarantine gateway provider');
    const sha256 = createHash('sha256').update(content).digest('hex');
    const size = content.byteLength;

    const result = await provider.putIfAbsent({
      bucket: S3_QUARANTINE_BUCKET,
      key,
      body: content,
      contentType: 'text/plain',
    });

    expect(result.bucket).toBe(S3_QUARANTINE_BUCKET);
    expect(result.key).toBe(key);
    expect(result.versionId).toBeDefined();
    expect(typeof result.versionId).toBe('string');
    expect(result.versionId.length).toBeGreaterThan(0);
    expect(result.sha256).toBe(sha256);
    expect(result.size).toBe(size);
  });

  // TEST P9-02 (Routing S3-02 through S3Provider): WRITE-ONCE / DUPLICATE REJECTION
  it('P9-02: putIfAbsent rejects duplicate write with AlreadyExists (HTTP 412)', async () => {
    const appId = randomUUID();
    const uploadId = randomUUID();
    const key = buildQuarantineKey(appId, uploadId);
    const content = Buffer.from('initial write-once quarantine object');

    // First upload succeeds
    const firstPut = await provider.putIfAbsent({
      bucket: S3_QUARANTINE_BUCKET,
      key,
      body: content,
    });
    expect(firstPut.versionId).toBeTruthy();

    // Duplicate upload to the same key MUST fail with AlreadyExists
    await expect(
      provider.putIfAbsent({
        bucket: S3_QUARANTINE_BUCKET,
        key,
        body: Buffer.from('attempted overwrite payload'),
      }),
    ).rejects.toThrow(AlreadyExists);
  });

  // TEST P9-03 (Routing S3-03 through S3Provider): EXACT OLD VERSION RETRIEVAL
  it('P9-03: getByVersion returns exact historical content by VersionId', async () => {
    const key = `incoming/p9-history/${randomUUID()}`;
    const contentV1 = 'quarantine-version-one-alpha';
    const contentV2 = 'quarantine-version-two-beta';

    // S3Provider enforces write-once, but S3 versioning allows historical versions
    // To simulate multiple versions for retrieval test, upload v1 and v2 via raw S3
    const put1 = await rawS3.send(
      new (await import('@aws-sdk/client-s3')).PutObjectCommand({
        Bucket: S3_QUARANTINE_BUCKET,
        Key: key,
        Body: Buffer.from(contentV1),
      }),
    );
    const v1 = put1.VersionId!;
    expect(v1).toBeTruthy();

    const put2 = await rawS3.send(
      new (await import('@aws-sdk/client-s3')).PutObjectCommand({
        Bucket: S3_QUARANTINE_BUCKET,
        Key: key,
        Body: Buffer.from(contentV2),
      }),
    );
    const v2 = put2.VersionId!;
    expect(v2).toBeTruthy();
    expect(v1).not.toBe(v2);

    // Retrieve V1 explicitly via provider
    const get1 = await provider.getByVersion({
      bucket: S3_QUARANTINE_BUCKET,
      key,
      versionId: v1,
    });
    const chunks1: Buffer[] = [];
    for await (const chunk of get1.body) {
      chunks1.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const retrieved1 = Buffer.concat(chunks1).toString('utf-8');
    expect(retrieved1).toBe(contentV1);
    expect(get1.versionId).toBe(v1);

    // Retrieve V2 explicitly via provider
    const get2 = await provider.getByVersion({
      bucket: S3_QUARANTINE_BUCKET,
      key,
      versionId: v2,
    });
    const chunks2: Buffer[] = [];
    for await (const chunk of get2.body) {
      chunks2.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const retrieved2 = Buffer.concat(chunks2).toString('utf-8');
    expect(retrieved2).toBe(contentV2);
    expect(get2.versionId).toBe(v2);
  });

  // TEST P9-04: NON-EXISTENT VERSION FAILS WITH VersionMissing AND NEVER FALLS BACK
  it('P9-04: getByVersion throws VersionMissing when versionId does not exist', async () => {
    const key = `incoming/p9-notfound/${randomUUID()}`;
    const putRes = await provider.putIfAbsent({
      bucket: S3_QUARANTINE_BUCKET,
      key,
      body: Buffer.from('existing content'),
    });
    expect(putRes.versionId).toBeTruthy();

    // Query non-existent versionId
    const bogusVersionId = 'nonexistent-version-id-99999999';
    await expect(
      provider.getByVersion({
        bucket: S3_QUARANTINE_BUCKET,
        key,
        versionId: bogusVersionId,
      }),
    ).rejects.toThrow(VersionMissing);
  });

  // TEST P9-05: EMPTY VERSION ID REJECTED WITH InvalidRequest
  it('P9-05: getByVersion rejects empty versionId with InvalidRequest', async () => {
    await expect(
      provider.getByVersion({
        bucket: S3_QUARANTINE_BUCKET,
        key: 'some-key',
        versionId: '',
      }),
    ).rejects.toThrow(InvalidRequest);
  });

  // TEST P9-06 (Routing S3-04 through S3Provider): SHA-256 ROUND TRIP SURVIVAL
  it('P9-06: SHA-256 digest and byte size survive the storage round trip identically', async () => {
    const key = `incoming/p9-sha/${randomUUID()}`;
    const content = Buffer.alloc(1024 * 32);
    for (let i = 0; i < content.length; i++) {
      content[i] = (i * 37 + 19) & 0xff;
    }

    const sha256Before = createHash('sha256').update(content).digest('hex');
    const sizeBefore = content.byteLength;

    const putRes = await provider.putIfAbsent({
      bucket: S3_QUARANTINE_BUCKET,
      key,
      body: content,
      checksumSha256: sha256Before,
    });
    expect(putRes.sha256).toBe(sha256Before);

    const getRes = await provider.getByVersion({
      bucket: S3_QUARANTINE_BUCKET,
      key,
      versionId: putRes.versionId,
    });

    const chunks: Buffer[] = [];
    for await (const chunk of getRes.body) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const retrievedBytes = Buffer.concat(chunks);
    const sha256After = createHash('sha256').update(retrievedBytes).digest('hex');

    expect(sha256After).toBe(sha256Before);
    expect(retrievedBytes.byteLength).toBe(sizeBefore);
  });

  // TEST P9-07: HEAD LOOKUP BY EXACT VERSION
  it('P9-07: head returns accurate metadata and contentLength by versionId', async () => {
    const key = `incoming/p9-head/${randomUUID()}`;
    const content = Buffer.from('metadata-head-test-content');
    const putRes = await provider.putIfAbsent({
      bucket: S3_QUARANTINE_BUCKET,
      key,
      body: content,
      contentType: 'application/octet-stream',
      metadata: { 'x-sug-test': 'integration' },
    });

    const headRes = await provider.head({
      bucket: S3_QUARANTINE_BUCKET,
      key,
      versionId: putRes.versionId,
    });

    expect(headRes.bucket).toBe(S3_QUARANTINE_BUCKET);
    expect(headRes.key).toBe(key);
    expect(headRes.versionId).toBe(putRes.versionId);
    expect(headRes.contentLength).toBe(content.byteLength);
    expect(headRes.contentType).toContain('application/octet-stream');
    expect(headRes.metadata?.['x-sug-test']).toBe('integration');
  });
});
