# Prompt
Read cwe.yaml and determine if any of those CWEs are not yet present in cbom-security.yaml. If a CWE is not in cbom-security.yaml, add it.

# Gap Analysis Result

## CWEs already covered (no action needed)
| CWE | Name | Covered by |
|-----|------|-----------|
| CWE-326 | Inadequate Encryption Strength | CBS-003 (key size < 128 bits) |
| CWE-327 | Use of Broken/Risky Cryptographic Algorithm | CBS-001 (MD5, SHA-1, RC4, DES, etc.) |
| CWE-328 | Use of Weak Hash | CBS-001 (subset of same condition) |

## CWEs added to cbom-security.yaml
| New Rule ID | CWE | Name | Severity |
|-------------|-----|------|----------|
| CBS-005 | CWE-259  | Use of Hard-coded Password | high |
| CBS-006 | CWE-321  | Use of Hard-coded Cryptographic Key | critical |
| CBS-007 | CWE-335  | Incorrect Usage of Seeds in PRNG | high |
| CBS-008 | CWE-338  | Use of Cryptographically Weak PRNG | critical |
| CBS-009 | CWE-759  | Use of a One-Way Hash without a Salt | high |
| CBS-010 | CWE-780  | Use of RSA Algorithm without OAEP | high |
| CBS-011 | CWE-916  | Use of Password Hash With Insufficient Computational Effort | critical |
| CBS-012 | CWE-1204 | Generation of Weak Initialization Vector (IV) | high |

## Files modified
- cbom-security.yaml — 8 new rules appended (CBS-005 through CBS-012), change history entry added to header comment.
