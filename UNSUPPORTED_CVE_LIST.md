# Unsupported CVEs

This document lists transient execution CVEs that have been evaluated and determined to be **out of scope** for this tool. See the [Which rules are governing the support of a CVE in this tool?](dist/FAQ.md#which-rules-are-governing-the-support-of-a-cve-in-this-tool) section in the FAQ for the general policy.

## CVE-2024-36348 — AMD Transient Scheduler Attack (UMIP bypass)

**Bulletin:** [AMD-SB-7029](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7029.html)
**CVSS:** 3.8 (Low)

A transient execution vulnerability in some AMD processors may allow a user process to speculatively infer CPU configuration registers even when UMIP is enabled.

**Why out of scope:** AMD has determined that "leakage of CPU Configuration does not result in leakage of sensitive information" and has marked this CVE as "No fix planned" across all affected product lines. No microcode or kernel mitigations have been issued, leaving nothing for this script to check.

## CVE-2024-36349 — AMD Transient Scheduler Attack (TSC_AUX leak)

**Bulletin:** [AMD-SB-7029](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7029.html)
**CVSS:** 3.8 (Low)

A transient execution vulnerability in some AMD processors may allow a user process to infer TSC_AUX even when such a read is disabled.

**Why out of scope:** AMD has determined that "leakage of TSC_AUX does not result in leakage of sensitive information" and has marked this CVE as "No fix planned" across all affected product lines. No microcode or kernel mitigations have been issued, leaving nothing for this script to check.
