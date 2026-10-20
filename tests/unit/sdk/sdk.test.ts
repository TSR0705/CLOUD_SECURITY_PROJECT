import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SugClient, SugApiError } from '@sug/sdk';

describe('SugClient & SugApiError Unit Tests', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('SugApiError', () => {
    it('constructs with full RFC 7807 problem details', () => {
      const err = new SugApiError(404, {
        type: 'urn:sug:error:not-found',
        title: 'Not Found',
        status: 404,
        detail: 'The requested resource does not exist',
        instance: '/api/v1/files/file-123',
        requestId: 'req-xyz-999',
        details: { entity: 'file', entityId: 'file-123' },
      });

      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(SugApiError);
      expect(err.name).toBe('SugApiError');
      expect(err.status).toBe(404);
      expect(err.type).toBe('urn:sug:error:not-found');
      expect(err.title).toBe('Not Found');
      expect(err.detail).toBe('The requested resource does not exist');
      expect(err.instance).toBe('/api/v1/files/file-123');
      expect(err.requestId).toBe('req-xyz-999');
      expect(err.details).toEqual({ entity: 'file', entityId: 'file-123' });
    });

    it('redacts sensitive tokens in safe toString() representation', () => {
      const err = new SugApiError(401, {
        title: 'Unauthorized',
        detail: 'Invalid credentials provided',
        requestId: 'req-auth-001',
      });

      const str = err.toString();
      expect(str).toContain('SugApiError [401]');
      expect(str).toContain('Unauthorized');
      expect(str).toContain('Invalid credentials provided');
      expect(str).toContain('req-auth-001');
      // Must not leak raw auth header or token string
      expect(str).not.toContain('sug_live_');
    });

    it('falls back to default title and detail when omitted', () => {
      const err = new SugApiError(500, {});
      expect(err.title).toBe('API Error');
      expect(err.detail).toBe('HTTP 500 API error');
      expect(err.type).toBe('urn:sug:error:http-500');
    });
  });

  describe('SugClient Configuration', () => {
    it('throws if baseUrl is empty', () => {
      expect(() => new SugClient({ baseUrl: '' })).toThrow(
        'SugClient requires a non-empty baseUrl',
      );
    });

    it('normalizes trailing slashes on baseUrl', async () => {
      let requestedUrl = '';
      globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
        requestedUrl = url;
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      });

      const client = new SugClient({ baseUrl: 'http://localhost:3000///', apiKey: 'sug_test_key' });
      await client.getUploadSession('sess-1');
      expect(requestedUrl).toBe('http://localhost:3000/api/v1/upload/sess-1/status');
    });
  });

  describe('Upload Sessions', () => {
    it('creates an upload session with apiKey', async () => {
      let capturedHeaders: Headers | undefined;
      let capturedBody: string | undefined;

      globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        capturedHeaders = init?.headers as Headers;
        capturedBody = init?.body as string;
        return new Response(
          JSON.stringify({
            sessionId: 'sess-abc',
            uploadToken: 'tok-xyz',
            tokenJti: 'jti-123',
            expiresAt: '2026-10-21T00:00:00Z',
            expiresInSeconds: 900,
            quarantineKey: 'quarantine/app/sess-abc.bin',
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        );
      });

      const client = new SugClient({
        baseUrl: 'http://localhost:3000',
        apiKey: 'sug_dev_tenant_key',
      });

      const res = await client.createUploadSession({
        filename: 'report.pdf',
        declaredSize: 1024,
        declaredMime: 'application/pdf',
      });

      expect(res.sessionId).toBe('sess-abc');
      expect(res.uploadToken).toBe('tok-xyz');
      expect(capturedHeaders?.get('Authorization')).toBe('Bearer sug_dev_tenant_key');
      expect(capturedHeaders?.get('Content-Type')).toBe('application/json');
      expect(JSON.parse(capturedBody!)).toEqual({
        filename: 'report.pdf',
        declaredSize: 1024,
        declaredMime: 'application/pdf',
      });
    });

    it('supports apiKey override per request', async () => {
      let capturedAuth: string | null = null;
      globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        const headers = init?.headers as Headers;
        capturedAuth = headers?.get('Authorization') ?? null;
        return new Response(JSON.stringify({ id: 'sess-1' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      });

      const client = new SugClient({
        baseUrl: 'http://localhost:3000',
        apiKey: 'sug_default_key',
      });

      await client.getUploadSession('sess-1', 'sug_override_key');
      expect(capturedAuth).toBe('Bearer sug_override_key');
    });

    it('aborts upload session with POST abort endpoint', async () => {
      let capturedMethod = '';
      globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        capturedMethod = init?.method ?? '';
        return new Response(null, { status: 204 });
      });

      const client = new SugClient({
        baseUrl: 'http://localhost:3000',
        apiKey: 'sug_key',
      });

      await client.abortUploadSession('sess-abort');
      expect(capturedMethod).toBe('POST');
    });
  });

  describe('Streaming Upload and High-Level Workflow', () => {
    it('uploads octet-stream bytes with Bearer uploadToken', async () => {
      let capturedAuth: string | null = null;
      let capturedContentLength: string | null = null;
      let capturedMethod = '';

      globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        capturedMethod = init?.method ?? '';
        const headers = init?.headers as Headers;
        capturedAuth = headers?.get('Authorization') ?? null;
        capturedContentLength = headers?.get('Content-Length') ?? null;

        return new Response(
          JSON.stringify({
            fileId: 'f-1',
            fileVersionId: 'fv-1',
            scanJobId: 'job-1',
            status: 'PENDING_SCAN',
            versionId: '1',
            size: 11,
            sha256: 'mockhash',
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        );
      });

      const client = new SugClient({ baseUrl: 'http://localhost:3000' });
      const payload = Buffer.from('hello world');

      const res = await client.upload('sess-123', 'sug_upload_token_999', payload);
      expect(capturedMethod).toBe('PUT');
      expect(capturedAuth).toBe('Bearer sug_upload_token_999');
      expect(capturedContentLength).toBe('11');
      expect(res.fileId).toBe('f-1');
    });

    it('uploadFile chains session creation and streaming upload', async () => {
      const calls: string[] = [];

      globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
        calls.push(url);
        if (url.includes('/api/v1/upload/session')) {
          return new Response(
            JSON.stringify({
              sessionId: 's-flow',
              uploadToken: 'tok-flow',
              quarantineKey: 'k-flow',
            }),
            { status: 201, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(
          JSON.stringify({
            fileId: 'f-flow',
            fileVersionId: 'fv-flow',
            scanJobId: 'job-flow',
            status: 'PENDING_SCAN',
            size: 5,
            sha256: 'dummy',
          }),
          { status: 201, headers: { 'Content-Type': 'application/json' } },
        );
      });

      const client = new SugClient({ baseUrl: 'http://localhost:3000', apiKey: 'key-1' });
      const result = await client.uploadFile({
        filename: 'test.txt',
        payload: 'test1',
      });

      expect(result.sessionId).toBe('s-flow');
      expect(result.fileId).toBe('f-flow');
      expect(calls).toHaveLength(2);
      expect(calls[0]).toContain('/api/v1/upload/session');
      expect(calls[1]).toContain('/api/v1/upload/s-flow');
    });
  });

  describe('Scans and Decisions', () => {
    it('retrieves scan result', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            scanJobId: 'job-1',
            scanStatus: 'SUCCEEDED',
            fileVersionId: 'fv-1',
            applicationId: 'app-1',
            findings: [
              { checkId: 'clamav', outcome: 'PASS', severity: 'INFO', confidence: 'CONFIRMED' },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const client = new SugClient({ baseUrl: 'http://localhost:3000', apiKey: 'key' });
      const scan = await client.getScan('job-1');
      expect(scan.scanJobId).toBe('job-1');
      expect(scan.findings).toHaveLength(1);
      expect(scan.findings[0]?.outcome).toBe('PASS');
    });

    it('submits human review decision override with user JWT', async () => {
      let capturedAuth: string | null = null;
      let capturedBody: string | undefined;

      globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
        const headers = init?.headers as Headers;
        capturedAuth = headers?.get('Authorization') ?? null;
        capturedBody = init?.body as string;
        return new Response(
          JSON.stringify({
            id: 'dec-rev',
            decision: 'ALLOW',
            action: 'ALLOW',
            fileVersionId: 'fv-rev',
            justification: 'Audited clean document false positive',
            decidedBy: 'user-analyst-1',
            supersedesId: 'dec-orig',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      });

      const client = new SugClient({
        baseUrl: 'http://localhost:3000',
        userToken: 'jwt_analyst_token',
      });

      const res = await client.reviewDecision('dec-orig', {
        action: 'ALLOW',
        justification: 'Audited clean document false positive',
      });

      expect(res.decision).toBe('ALLOW');
      expect(capturedAuth).toBe('Bearer jwt_analyst_token');
      expect(JSON.parse(capturedBody!)).toEqual({
        action: 'ALLOW',
        justification: 'Audited clean document false positive',
      });
    });
  });

  describe('File Downloads and Metadata', () => {
    it('downloads clean decrypted file and extracts cryptographic headers', async () => {
      const fileBytes = Buffer.from('%PDF-1.7 clean test content');

      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(fileBytes, {
          status: 200,
          headers: {
            'Content-Type': 'application/pdf',
            'X-SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'Content-Disposition': 'attachment; filename="doc.pdf"',
          },
        }),
      );

      const client = new SugClient({ baseUrl: 'http://localhost:3000', apiKey: 'key' });
      const dl = await client.downloadFile('file-99');

      expect(dl.contentType).toBe('application/pdf');
      expect(dl.sha256).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      expect(dl.data.toString()).toBe('%PDF-1.7 clean test content');
    });

    it('throws SugApiError when download returns 403 or 404', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            type: 'urn:sug:error:forbidden',
            title: 'Forbidden',
            status: 403,
            detail: 'Cross-tenant file access denied',
            requestId: 'req-err-403',
          }),
          { status: 403, headers: { 'Content-Type': 'application/problem+json' } },
        ),
      );

      const client = new SugClient({ baseUrl: 'http://localhost:3000', apiKey: 'alien_key' });
      await expect(client.downloadFile('file-other-tenant')).rejects.toThrow(SugApiError);
    });
  });

  describe('Audit and Hash Chain Verification', () => {
    it('queries security events with filters', async () => {
      let queryUrl = '';
      globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
        queryUrl = url;
        return new Response(
          JSON.stringify({
            events: [
              {
                seq: 1,
                id: 'evt-1',
                action: 'file.upload_started',
                occurred_at: '2026-10-20T10:00:00Z',
                actor_type: 'API_KEY',
                actor_id: 'key-1',
                prev_hash: '0000000000000000000000000000000000000000000000000000000000000000',
                event_hash: 'abc123hash',
                details: {},
                application_id: 'app-1',
                file_id: null,
                file_version_id: null,
                decision_id: null,
                request_id: 'req-1',
              },
            ],
            pagination: { limit: 10, has_more: false },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      });

      const client = new SugClient({ baseUrl: 'http://localhost:3000', apiKey: 'key' });
      const events = await client.getSecurityEvents({ action: 'file.upload_started', limit: 10 });

      expect(queryUrl).toContain('action=file.upload_started');
      expect(queryUrl).toContain('limit=10');
      expect(events.events).toHaveLength(1);
      expect(events.events[0]?.action).toBe('file.upload_started');
    });

    it('verifies audit hash chain via verifyAuditChain', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            verified: true,
            totalEvents: 42,
            startSeq: 1,
            endSeq: 42,
            chainHash: 'fedcba987654321',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const client = new SugClient({ baseUrl: 'http://localhost:3000', userToken: 'admin_jwt' });
      const result = await client.verifyAuditChain({ fromSeq: 1, toSeq: 42 });
      expect(result.verified).toBe(true);
      expect(result.totalEvents).toBe(42);
    });
  });
});
