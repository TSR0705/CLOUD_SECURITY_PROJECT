rule P15_Test_Malware_Signature {
  meta:
    description = "Canonical P15 test malware pattern for scan-03"
    severity = "critical"
    confidence = "high"
  strings:
    $sig = "SUG_MALWARE_TEST_PATTERN_P15_THREAT"
  condition:
    $sig
}
