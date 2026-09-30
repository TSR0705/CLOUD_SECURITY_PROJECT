rule P15_Secondary_Test_Signature {
  meta:
    description = "Secondary test threat pattern for multiple match verification"
    severity = "high"
    confidence = "medium"
  strings:
    $sig = "SUG_SECONDARY_TEST_PATTERN_P15_THREAT"
  condition:
    $sig
}
