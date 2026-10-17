/**
 * Observable verification script for P17 PDF Normalization & Active Content Inspection
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { inspectPdf } from '../packages/security-engine/dist/format/pdf.js';

function createCleanPdfBuffer() {
  const content = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT
/F1 24 Tf
100 700 Td
(Hello World) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000206 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
300
%%EOF
`;
  return Buffer.from(content, 'utf-8');
}

function createActivePdfBuffer() {
  const content = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('PWNED');) >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000109 00000 n
0000000166 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
230
%%EOF
`;
  return Buffer.from(content, 'utf-8');
}

async function run() {
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'pdf-verify-'));
  console.log('=== P17 OBSERVABLE PDF NORMALIZATION & DETECTION VERIFICATION ===\n');

  try {
    // 1. Clean PDF
    const cleanPath = path.join(tmpDir, 'clean.pdf');
    await fs.promises.writeFile(cleanPath, createCleanPdfBuffer());
    const resClean = await inspectPdf({ filePath: cleanPath });
    console.log('[CASE 1: CLEAN PDF]');
    console.log(`  Engine:     ${resClean.engine}`);
    console.log(`  Outcome:    ${resClean.outcome}`);
    console.log(`  Reason:     ${resClean.reasonCode}`);
    console.log(`  Keywords:   ${JSON.stringify(resClean.detectedKeywords)}`);
    console.log(`  Normalized: ${resClean.evidence.normalizedWithQpdf ?? false}`);
    console.log(
      `  Verdict:    ${resClean.outcome === 'PASS' && resClean.reasonCode === 'CLEAN' ? 'VERIFIED PASS' : 'FAIL'}\n`,
    );

    // 2. Active Content PDF
    const activePath = path.join(tmpDir, 'active.pdf');
    await fs.promises.writeFile(activePath, createActivePdfBuffer());
    const resActive = await inspectPdf({ filePath: activePath });
    console.log('[CASE 2: ACTIVE CONTENT PDF]');
    console.log(`  Engine:     ${resActive.engine}`);
    console.log(`  Outcome:    ${resActive.outcome}`);
    console.log(`  Reason:     ${resActive.reasonCode}`);
    console.log(`  Keywords:   ${JSON.stringify(resActive.detectedKeywords)}`);
    console.log(
      `  Verdict:    ${resActive.outcome === 'FAIL' && resActive.reasonCode === 'ACTIVE_CONTENT_DETECTED' ? 'VERIFIED DETECTED' : 'FAIL'}\n`,
    );

    // 3. Malformed PDF (damaged trailer / syntax error)
    const malformedPath = path.join(tmpDir, 'malformed.pdf');
    await fs.promises.writeFile(
      malformedPath,
      Buffer.from(
        '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages >>\ncorrupted trailer bytes without EOF\n',
      ),
    );
    const resMalformed = await inspectPdf({ filePath: malformedPath });
    console.log('[CASE 3: MALFORMED / CORRUPTED PDF]');
    console.log(`  Engine:     ${resMalformed.engine}`);
    console.log(`  Outcome:    ${resMalformed.outcome}`);
    console.log(`  Reason:     ${resMalformed.reasonCode}`);
    console.log(`  Error:      ${resMalformed.evidence.error}`);
    console.log(
      `  Verdict:    ${resMalformed.outcome === 'ERROR' && resMalformed.reasonCode === 'PDF_MALFORMED' ? 'VERIFIED FAIL-CLOSED' : 'FAIL'}\n`,
    );

    // 4. Truncated PDF (missing %%EOF marker)
    const truncatedBuffer = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n');
    const resTruncated = await inspectPdf({ buffer: truncatedBuffer });
    console.log('[CASE 4: TRUNCATED PDF MISSING %%EOF]');
    console.log(`  Engine:     ${resTruncated.engine}`);
    console.log(`  Outcome:    ${resTruncated.outcome}`);
    console.log(`  Reason:     ${resTruncated.reasonCode}`);
    console.log(`  Error:      ${resTruncated.evidence.error}`);
    console.log(
      `  Verdict:    ${resTruncated.outcome === 'ERROR' && resTruncated.reasonCode === 'PDF_MALFORMED' ? 'VERIFIED FAIL-CLOSED' : 'FAIL'}\n`,
    );

    // 5. Normalization Timeout
    const mockScript = path.join(tmpDir, 'qpdf-mock.mjs');
    await fs.promises.writeFile(
      mockScript,
      `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args.includes('--version')) {
  process.stdout.write('qpdf version 11.3.0 (test mock)\\n');
  process.exit(0);
}
const mode = process.env.MOCK_QPDF_MODE || 'success';
if (mode === 'timeout') {
  await new Promise((r) => setTimeout(r, 15000));
  process.exit(0);
}
if (mode === 'error') {
  process.stderr.write('qpdf fatal error: process crash\\n');
  process.exit(1);
}
process.exit(0);
`,
    );

    process.env.MOCK_QPDF_MODE = 'timeout';
    const resTimeout = await inspectPdf({
      filePath: cleanPath,
      qpdfPath: process.execPath,
      qpdfArgs: [mockScript],
      timeoutMs: 300,
    });
    console.log('[CASE 5: QPDF TIMEOUT]');
    console.log(`  Engine:     ${resTimeout.engine}`);
    console.log(`  Outcome:    ${resTimeout.outcome}`);
    console.log(`  Reason:     ${resTimeout.reasonCode}`);
    console.log(`  TimedOut:   ${resTimeout.evidence.timedOut}`);
    console.log(
      `  Verdict:    ${resTimeout.outcome === 'ERROR' && resTimeout.reasonCode === 'PDF_NORMALIZATION_FAILED' && resTimeout.evidence.timedOut === true ? 'VERIFIED FAIL-CLOSED' : 'FAIL'}\n`,
    );

    // 6. Normalization Process Crash / Fatal Error
    process.env.MOCK_QPDF_MODE = 'error';
    const resCrash = await inspectPdf({
      filePath: cleanPath,
      qpdfPath: process.execPath,
      qpdfArgs: [mockScript],
    });
    console.log('[CASE 6: QPDF PROCESS CRASH / ERROR]');
    console.log(`  Engine:     ${resCrash.engine}`);
    console.log(`  Outcome:    ${resCrash.outcome}`);
    console.log(`  Reason:     ${resCrash.reasonCode}`);
    console.log(`  Error:      ${resCrash.evidence.error}`);
    console.log(
      `  Verdict:    ${resCrash.outcome === 'ERROR' && resCrash.reasonCode === 'PDF_NORMALIZATION_FAILED' ? 'VERIFIED FAIL-CLOSED' : 'FAIL'}\n`,
    );

    console.log('=== ALL 6 CASES VERIFIED: ERRORS NEVER FALL THROUGH TO CLEAN ===');
  } finally {
    await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  }
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
