# Unsupported CVEs

This document lists transient execution CVEs that have been evaluated and determined to be **out of scope** for this tool. See the [Which rules are governing the support of a CVE in this tool?](dist/FAQ.md#which-rules-are-governing-the-support-of-a-cve-in-this-tool) section in the FAQ for the general policy.

## CVE-2018-9056 — BranchScope

**Issue:** [#169](https://github.com/speed47/spectre-meltdown-checker/issues/169)
**Research paper:** [BranchScope (ASPLOS 2018)](http://www.cs.ucr.edu/~nael/pubs/asplos18.pdf)
**Red Hat bug:** [#1561794](https://bugzilla.redhat.com/show_bug.cgi?id=1561794)
**CVSS:** 5.6 (Medium)

A speculative execution attack exploiting the directional branch predictor, allowing an attacker to infer data by manipulating the shared branch prediction state (pattern history table). Initially demonstrated on Intel processors.

**Why out of scope:** No kernel or microcode mitigations have been issued. Red Hat closed their tracking bug as "CLOSED CANTFIX", concluding that "this is a hardware processor issue, not a Linux kernel flaw" and that "it is specific to a target software which uses sensitive information in branching expressions." The mitigation responsibility falls on individual software to avoid using sensitive data in conditional branches, which is out of the scope of this tool.

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
