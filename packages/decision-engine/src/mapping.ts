/**
 * @sug/decision-engine/mapping
 * Check identifier mapping and resolution between policy requiredChecks and scanner findings.
 */

const CANONICAL_CHECK_MAP: Readonly<Record<string, readonly string[]>> = {
  // ClamAV
  'clamav.instream': ['scanner.clamav', 'clamav.instream', 'clamav'],
  'scanner.clamav': ['scanner.clamav', 'clamav.instream', 'clamav'],

  // YARA
  'yara.rules': ['scanner.yara', 'yara.rules', 'yara'],
  'scanner.yara': ['scanner.yara', 'yara.rules', 'yara'],

  // Archive
  'archive.bomb': ['scanner.archive', 'archive.bomb', 'archive'],
  'archive.traversal': ['scanner.archive', 'archive.traversal', 'archive'],
  'archive.integrity': ['scanner.archive', 'archive.integrity', 'archive'],
  'scanner.archive': [
    'scanner.archive',
    'archive.bomb',
    'archive.traversal',
    'archive.integrity',
    'archive',
  ],

  // PDF
  'pdf.active_content': ['scanner.pdf', 'pdf.active_content', 'pdf'],
  'pdf.encrypted': ['scanner.pdf', 'pdf.encrypted', 'pdf'],
  'pdf.embedded': ['scanner.pdf', 'pdf.embedded', 'pdf'],
  'scanner.pdf': ['scanner.pdf', 'pdf.active_content', 'pdf.encrypted', 'pdf.embedded', 'pdf'],

  // Office / OOXML
  'office.macros': ['scanner.ooxml.macro', 'scanner.ooxml.relationship', 'office.macros', 'ooxml'],
  'scanner.ooxml.macro': ['scanner.ooxml.macro', 'office.macros'],
  'scanner.ooxml.relationship': ['scanner.ooxml.relationship', 'office.macros'],

  // Images
  'image.format': ['scanner.image.trailing', 'scanner.signature.embedded', 'image.format', 'image'],
  'scanner.image.trailing': ['scanner.image.trailing', 'image.format'],
  'scanner.signature.embedded': ['scanner.signature.embedded', 'image.format'],

  // Polyglot
  'polyglot.basic': ['scanner.polyglot', 'polyglot.basic', 'polyglot'],
  'scanner.polyglot': ['scanner.polyglot', 'polyglot.basic', 'polyglot'],

  // P11 Ingest Validators
  'filename.safe': ['validator.filename', 'filename.safe', 'filename'],
  'extension.allowed': ['validator.extension', 'extension.allowed', 'extension'],
  'magic.detect': ['validator.magic', 'magic.detect', 'magic'],
  'type.consistency': ['validator.type', 'type.consistency', 'type'],
  'size.limit': ['validator.size', 'size.limit', 'size'],
};

/**
 * Normalizes a check identifier for fuzzy comparison.
 */
function normalizeCheckId(id: string): string {
  return id.trim().toLowerCase();
}

/**
 * Checks whether a finding check identifier satisfies a required policy check.
 */
export function checkMatches(policyCheck: string, findingCheckId: string): boolean {
  const normPolicy = normalizeCheckId(policyCheck);
  const normFinding = normalizeCheckId(findingCheckId);

  if (normPolicy === normFinding) {
    return true;
  }

  // Check aliases from canonical map
  const policyAliases = CANONICAL_CHECK_MAP[normPolicy];
  if (policyAliases && policyAliases.includes(normFinding)) {
    return true;
  }

  const findingAliases = CANONICAL_CHECK_MAP[normFinding];
  if (findingAliases && findingAliases.includes(normPolicy)) {
    return true;
  }

  // Strip prefixes (e.g. 'scanner.', 'validator.')
  const strippedPolicy = normPolicy.replace(/^(scanner\.|validator\.)/, '');
  const strippedFinding = normFinding.replace(/^(scanner\.|validator\.)/, '');

  if (strippedPolicy === strippedFinding) {
    return true;
  }

  return false;
}

/**
 * Determines whether a required policy check is satisfied by at least one finding in the set.
 */
export function isRequiredCheckSatisfied(
  policyCheck: string,
  findingCheckIds: readonly string[],
): boolean {
  for (const fId of findingCheckIds) {
    if (checkMatches(policyCheck, fId)) {
      return true;
    }
  }
  return false;
}
