import { describe, it, expect, beforeAll } from 'vitest';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  CreateBucketCommand,
  PutBucketVersioningCommand,
} from '@aws-sdk/client-s3';
import { createHash, randomUUID } from 'node:crypto';

const S3_ENDPOINT = process.env.S3_ENDPOINT || 'http://localhost:4566';
const GCS_ENDPOINT = process.env.GCS_ENDPOINT || 'http://localhost:4443';
const S3_QUARANTINE_BUCKET = 'sug-quarantine-local';
const GCS_REPLICA_BUCKET = 'sug-replica-local';

describe('Storage Assumption Spike (P2)', () => {
  let s3: S3Client;

  beforeAll(async () => {
    s3 = new S3Client({
      endpoint: S3_ENDPOINT,
      region: 'us-east-1',
      credentials: {
        accessKeyId: 'test',
        secretAccessKey: 'test',
      },
      forcePathStyle: true,
    });

    // Ensure S3 quarantine bucket exists with versioning
    try {
      await s3.send(new HeadBucketCommand({ Bucket: S3_QUARANTINE_BUCKET }));
    } catch {
      await s3.send(new CreateBucketCommand({ Bucket: S3_QUARANTINE_BUCKET }));
    }

    await s3.send(
      new PutBucketVersioningCommand({
        Bucket: S3_QUARANTINE_BUCKET,
        VersioningConfiguration: { Status: 'Enabled' },
      }),
    );

    // Ensure GCS replica bucket exists
    const gcsBucketRes = await fetch(`${GCS_ENDPOINT}/storage/v1/b/${GCS_REPLICA_BUCKET}`);
    if (gcsBucketRes.status === 404) {
      const createRes = await fetch(`${GCS_ENDPOINT}/storage/v1/b?project=test-project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: GCS_REPLICA_BUCKET }),
      });
      expect(createRes.ok).toBe(true);
    }
  });

  describe('S3 Assumptions (LocalStack Community)', () => {
    // TEST S3-01 — VERSIONED PUT
    it('S3-01: PutObject returns a valid, non-empty VersionId on versioned bucket', async () => {
      const key = `incoming/p2-test/upload-001/sample-${randomUUID()}.txt`;
      const content = Buffer.from('hello secure gateway');
      const sha256 = createHash('sha256').update(content).digest('hex');
      const size = content.byteLength;

      const putRes = await s3.send(
        new PutObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          Body: content,
          ChecksumAlgorithm: 'SHA256',
        }),
      );

      expect(putRes.VersionId).toBeDefined();
      expect(typeof putRes.VersionId).toBe('string');
      expect(putRes.VersionId!.length).toBeGreaterThan(0);

      // Verify recorded identity fields
      const record = {
        bucket: S3_QUARANTINE_BUCKET,
        key,
        versionId: putRes.VersionId!,
        sha256,
        size,
      };
      expect(record.bucket).toBe(S3_QUARANTINE_BUCKET);
      expect(record.key).toBe(key);
      expect(record.versionId).toBeTruthy();
      expect(record.sha256).toBe(sha256);
      expect(record.size).toBe(size);
    });

    // TEST S3-02 — CREATE-ONLY PUT
    it('S3-02: PutObject with If-None-Match:* rejects duplicate write on existing key', async () => {
      const key = `incoming/p2-test/create-only-${randomUUID()}.txt`;
      const contentV1 = Buffer.from('initial payload');

      // First upload succeeds
      const put1 = await s3.send(
        new PutObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          Body: contentV1,
        }),
      );
      expect(put1.VersionId).toBeDefined();

      // Second upload with If-None-Match: * MUST fail and not silently overwrite
      let caughtError: unknown = null;
      try {
        await s3.send(
          new PutObjectCommand({
            Bucket: S3_QUARANTINE_BUCKET,
            Key: key,
            Body: Buffer.from('unauthorized overwrite attempt'),
            IfNoneMatch: '*',
          }),
        );
      } catch (err) {
        caughtError = err;
      }

      expect(caughtError).toBeDefined();
      const s3Error = caughtError as {
        name?: string;
        $metadata?: { httpStatusCode?: number };
      };
      // PreconditionFailed maps to HTTP 412
      expect(
        s3Error.name === 'PreconditionFailed' || s3Error.$metadata?.httpStatusCode === 412,
      ).toBe(true);
    });

    // TEST S3-03 — OLD VERSION RETRIEVAL
    it('S3-03: GetObject by older VersionId returns original content after overwrite', async () => {
      const key = `incoming/p2-test/version-history-${randomUUID()}.txt`;
      const contentV1 = 'version-one';
      const contentV2 = 'version-two';

      // Upload V1
      const put1 = await s3.send(
        new PutObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          Body: Buffer.from(contentV1),
        }),
      );
      const v1 = put1.VersionId!;
      expect(v1).toBeTruthy();

      // Upload V2 to the same key
      const put2 = await s3.send(
        new PutObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          Body: Buffer.from(contentV2),
        }),
      );
      const v2 = put2.VersionId!;
      expect(v2).toBeTruthy();
      expect(v1).not.toBe(v2);

      // Retrieve V1 explicitly
      const get1 = await s3.send(
        new GetObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          VersionId: v1,
        }),
      );
      const body1 = await get1.Body!.transformToString();
      expect(body1).toBe(contentV1);

      // Retrieve V2 explicitly
      const get2 = await s3.send(
        new GetObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          VersionId: v2,
        }),
      );
      const body2 = await get2.Body!.transformToString();
      expect(body2).toBe(contentV2);
    });

    // TEST S3-04 — SHA-256 ROUND TRIP
    it('S3-04: SHA-256 digest and byte size survive the storage round trip identically', async () => {
      const key = `incoming/p2-test/sha-roundtrip-${randomUUID()}.bin`;
      // Generate deterministic pseudo-random binary content
      const content = Buffer.alloc(1024 * 16);
      for (let i = 0; i < content.length; i++) {
        content[i] = (i * 31 + 17) & 0xff;
      }

      const sha256Before = createHash('sha256').update(content).digest('hex');
      const sizeBefore = content.byteLength;

      const putRes = await s3.send(
        new PutObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          Body: content,
          ChecksumAlgorithm: 'SHA256',
        }),
      );
      const versionId = putRes.VersionId!;
      expect(versionId).toBeTruthy();

      const getRes = await s3.send(
        new GetObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          VersionId: versionId,
        }),
      );
      const retrievedBytes = Buffer.from(await getRes.Body!.transformToByteArray());
      const sha256After = createHash('sha256').update(retrievedBytes).digest('hex');
      const sizeAfter = retrievedBytes.byteLength;

      expect(sha256After).toBe(sha256Before);
      expect(sizeAfter).toBe(sizeBefore);
    });

    // TEST S3-05 — VERSION + HASH + SIZE IDENTITY
    it('S3-05: Storage interaction yields complete exact artifact identity record', async () => {
      const key = `incoming/p2-test/identity-${randomUUID()}.dat`;
      const content = Buffer.from('artifact identity binding payload');
      const sha256 = createHash('sha256').update(content).digest('hex');
      const size = content.byteLength;

      const putRes = await s3.send(
        new PutObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          Body: content,
        }),
      );

      const identityRecord = {
        bucket: S3_QUARANTINE_BUCKET,
        key,
        versionId: putRes.VersionId,
        sha256,
        size,
      };

      expect(identityRecord.bucket).toBe(S3_QUARANTINE_BUCKET);
      expect(identityRecord.key).toBe(key);
      expect(identityRecord.versionId).toBeDefined();
      expect(typeof identityRecord.versionId).toBe('string');
      expect(identityRecord.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(identityRecord.size).toBeGreaterThan(0);
    });

    // TEST S3-06 — OVERWRITE DOES NOT DESTROY OLD VERSION
    it('S3-06: Overwrite does not destroy or mutate historical artifact version', async () => {
      const key = `incoming/p2-test/immutability-${randomUUID()}.txt`;
      const contentV1 = Buffer.from('immutable-historical-content-v1');
      const sha1 = createHash('sha256').update(contentV1).digest('hex');
      const size1 = contentV1.byteLength;

      const put1 = await s3.send(
        new PutObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          Body: contentV1,
        }),
      );
      const v1 = put1.VersionId!;

      const contentV2 = Buffer.from('modified-content-v2-different-bytes');
      const sha2 = createHash('sha256').update(contentV2).digest('hex');
      const size2 = contentV2.byteLength;

      const put2 = await s3.send(
        new PutObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          Body: contentV2,
        }),
      );
      const v2 = put2.VersionId!;

      expect(v1).not.toBe(v2);

      // Verify V1 remains unchanged
      const get1 = await s3.send(
        new GetObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          VersionId: v1,
        }),
      );
      const bytes1 = Buffer.from(await get1.Body!.transformToByteArray());
      expect(createHash('sha256').update(bytes1).digest('hex')).toBe(sha1);
      expect(bytes1.byteLength).toBe(size1);

      // Verify V2 has new content
      const get2 = await s3.send(
        new GetObjectCommand({
          Bucket: S3_QUARANTINE_BUCKET,
          Key: key,
          VersionId: v2,
        }),
      );
      const bytes2 = Buffer.from(await get2.Body!.transformToByteArray());
      expect(createHash('sha256').update(bytes2).digest('hex')).toBe(sha2);
      expect(bytes2.byteLength).toBe(size2);
    });
  });

  describe('GCS Assumptions (fake-gcs-server JSON API)', () => {
    // TEST GCS-01 — CREATE WITH GENERATION PRECONDITION
    it('GCS-01: ifGenerationMatch=0 successfully creates a new object and returns generation', async () => {
      const objectName = `p2-test/gcs-create-${randomUUID()}.txt`;
      const url = `${GCS_ENDPOINT}/upload/storage/v1/b/${GCS_REPLICA_BUCKET}/o?uploadType=media&name=${encodeURIComponent(objectName)}&ifGenerationMatch=0`;

      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: 'replica test content initial creation',
      });

      expect(res.status).toBe(200);
      const metadata = (await res.json()) as {
        name: string;
        generation: string;
      };
      expect(metadata.name).toBe(objectName);
      expect(metadata.generation).toBeDefined();
      expect(typeof metadata.generation).toBe('string');
      expect(metadata.generation.length).toBeGreaterThan(0);
    });

    // TEST GCS-02 — CREATE-ONLY REPLAY
    it('GCS-02: Replay with ifGenerationMatch=0 is rejected with HTTP 412 on existing object', async () => {
      const objectName = `p2-test/gcs-replay-${randomUUID()}.txt`;
      const url = `${GCS_ENDPOINT}/upload/storage/v1/b/${GCS_REPLICA_BUCKET}/o?uploadType=media&name=${encodeURIComponent(objectName)}&ifGenerationMatch=0`;

      // First create succeeds
      const res1 = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: 'initial replica payload',
      });
      expect(res1.status).toBe(200);

      // Second create with ifGenerationMatch=0 MUST fail with HTTP 412
      const res2 = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: 'unauthorized replica overwrite',
      });
      expect(res2.status).toBe(412);

      const errorPayload = (await res2.json()) as {
        error?: { code?: number; message?: string };
      };
      expect(errorPayload.error?.code).toBe(412);
      expect(errorPayload.error?.message).toContain('Precondition failed');
    });

    // TEST GCS-03 — GENERATION VALUE
    it('GCS-03: GCS object exposes generation and subsequent update alters generation', async () => {
      const objectName = `p2-test/gcs-generation-${randomUUID()}.txt`;
      const createUrl = `${GCS_ENDPOINT}/upload/storage/v1/b/${GCS_REPLICA_BUCKET}/o?uploadType=media&name=${encodeURIComponent(objectName)}&ifGenerationMatch=0`;

      const createRes = await fetch(createUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: 'initial generation content',
      });
      expect(createRes.status).toBe(200);
      const createMeta = (await createRes.json()) as { generation: string };
      const gen1 = createMeta.generation;
      expect(gen1).toBeTruthy();

      // Update object without ifGenerationMatch=0 (or with matching generation)
      const updateUrl = `${GCS_ENDPOINT}/upload/storage/v1/b/${GCS_REPLICA_BUCKET}/o?uploadType=media&name=${encodeURIComponent(objectName)}`;
      const updateRes = await fetch(updateUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: 'updated generation content',
      });
      expect(updateRes.status).toBe(200);
      const updateMeta = (await updateRes.json()) as { generation: string };
      const gen2 = updateMeta.generation;
      expect(gen2).toBeTruthy();
      expect(gen1).not.toBe(gen2);
    });
  });
});
