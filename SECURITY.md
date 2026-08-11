# Security and evidence-handling model

DFIR Copilot is a student portfolio and training application. It is not a
replacement for validated forensic suites, organizational procedure, or expert
testimony.

## Evidence controls

- Imported evidence is copied into a case-specific directory.
- SHA-256 is calculated before and after the copy.
- Analysis reads the stored copy and stops when verification fails.
- Every import, verification, analysis, query, and report action is audited.
- Original source evidence is never modified by the application.

## AI privacy

Offline Copilot mode is the default. Groq mode is opt-in per query and sends a
bounded structured context containing extracted descriptions and references;
it does not upload original evidence files. Do not enable cloud mode for data
that policy, law, or client agreements prohibit from leaving the device.

## Safe demo

The demo contains no malware. It uses an RFC 5737 documentation address and an
RFC 2606 `.invalid` domain. The PowerShell-looking file ends in `.txt` and is
provided solely to test pattern detection.

## Reporting a problem

Do not include real evidence, secrets, API keys, or personal data in a public
issue. Rotate any key that is accidentally committed.

