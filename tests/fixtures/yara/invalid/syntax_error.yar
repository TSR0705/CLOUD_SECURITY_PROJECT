rule InvalidSyntaxRule {
  meta:
    description = "Deliberately invalid YARA rule fixture for P15 syntax failure gate"
  strings:
    $a = "test"
  condition:
    $a AND invalid syntax token here
}
