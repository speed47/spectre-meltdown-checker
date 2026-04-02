# Unsupported CVEs

This document lists transient execution CVEs that have been evaluated and determined to be **out of scope** for this tool. See the [Which rules are governing the support of a CVE in this tool?](dist/FAQ.md#which-rules-are-governing-the-support-of-a-cve-in-this-tool) section in the FAQ for the general policy.

## CVE-2018-9056 — BranchScope

- **Issue:** [#169](https://github.com/speed47/spectre-meltdown-checker/issues/169)
- **Research paper:** [BranchScope (ASPLOS 2018)](http://www.cs.ucr.edu/~nael/pubs/asplos18.pdf)
- **Red Hat bug:** [#1561794](https://bugzilla.redhat.com/show_bug.cgi?id=1561794)
- **CVSS:** 5.6 (Medium)

A speculative execution attack exploiting the directional branch predictor, allowing an attacker to infer data by manipulating the shared branch prediction state (pattern history table). Initially demonstrated on Intel processors.

**Why out of scope:** No kernel or microcode mitigations have been issued. Red Hat closed their tracking bug as "CLOSED CANTFIX", concluding that "this is a hardware processor issue, not a Linux kernel flaw" and that "it is specific to a target software which uses sensitive information in branching expressions." The mitigation responsibility falls on individual software to avoid using sensitive data in conditional branches, which is out of the scope of this tool.

## CVE-2018-3693 — Bounds Check Bypass Store (Spectre v1.1)

- **Issue:** [#236](https://github.com/speed47/spectre-meltdown-checker/issues/236)
- **Red Hat advisory:** [Speculative Store Bypass / Bounds Check Bypass (CVE-2018-3693)](https://access.redhat.com/solutions/3523601)
- **CVSS:** 5.6 (Medium)

A subvariant of Spectre V1 where speculative store operations can write beyond validated buffer boundaries before the bounds check resolves, allowing an attacker to alter cache state and leak information via side channels.

**Why out of scope:** The mitigations are identical to CVE-2017-5753 (Spectre V1): `lfence` instructions after bounds checks and `array_index_nospec()` barriers in kernel code. There is no separate sysfs entry, no new CPU feature flag, and no distinct microcode change. This tool's existing CVE-2017-5753 checks already detect these mitigations (`__user pointer sanitization`, `usercopy/swapgs barriers`), so CVE-2018-3693 is fully covered as part of Spectre V1.

## CVE-2018-15572 — SpectreRSB (Return Stack Buffer)

- **Issue:** [#224](https://github.com/speed47/spectre-meltdown-checker/issues/224)
- **Research paper:** [Spectre Returns! Speculation Attacks using the Return Stack Buffer (WOOT'18)](https://arxiv.org/abs/1807.07940)
- **Kernel fix:** [commit fdf82a7856b3](https://github.com/torvalds/linux/commit/fdf82a7856b32d905c39afc85e34364491e46346) (Linux 4.18.1)
- **CVSS:** 6.5 (Medium)

The `spectre_v2_select_mitigation` function in the Linux kernel before 4.18.1 did not always fill the RSB upon a context switch, allowing userspace-to-userspace SpectreRSB attacks on Skylake+ CPUs where an empty RSB falls back to 
he BTB.

**Why out of scope:** This CVE is a Spectre V2 mitigation gap (missing RSB filling on context switch), not a distinct hardware vulnerability. It is already fully covered by this tool's CVE-2017-5715 (Spectre V2) checks, which dete
ct whether the kernel performs RSB filling on CPUs vulnerable to RSB underflow (Skylake+ and RSBA-capable CPUs). A missing RSB fill is flagged as a caveat ("RSB filling missing on Skylake+") in the Spectre V2 verdict.

## CVE-2019-1125 — Spectre SWAPGS gadget

- **Issue:** [#301](https://github.com/speed47/spectre-meltdown-checker/issues/301)
- **Kernel fix:** [commit 18ec54fdd6d1](https://github.com/torvalds/linux/commit/18ec54fdd6d18d92025af097cd042a75cf0ea24c) (Linux 5.3)
- **CVSS:** 5.6 (Medium)

A Spectre V1 subvariant where the `SWAPGS` instruction can be speculatively executed on x86 CPUs, allowing an attacker to leak kernel memory via a side channel on the GS segment base value.

**Why out of scope:** This is a Spectre V1 subvariant whose mitigation (SWAPGS barriers) shares the same sysfs entry as CVE-2017-5753. This tool's existing CVE-2017-5753 checks already detect SWAPGS barriers: a mitigated kernel reports `"Mitigation: usercopy/swapgs barriers and __user pointer sanitization"`, while a kernel lacking the fix reports `"Vulnerable: __user pointer sanitization and usercopy barriers only; no swapgs barriers"`. CVE-2019-1125 is therefore fully covered as part of Spectre V1.

## CVE-2019-15902 — Spectre V1 backport regression

- **Issue:** [#304](https://github.com/speed47/spectre-meltdown-checker/issues/304)
- **CVSS:** 5.6 (Medium)

A backporting mistake in Linux stable/longterm kernel versions (4.4.x through 4.4.190, 4.9.x through 4.9.190, 4.14.x through 4.14.141, 4.19.x through 4.19.69, and 5.2.x through 5.2.11) swapped two code lines in `ptrace_get_debugreg()`, placing the `array_index_nospec()` call after the array access instead of before, reintroducing a Spectre V1 vulnerability.

**Why out of scope:** This is a kernel bug (bad backport), not a hardware vulnerability. The flawed code is not detectable on a running kernel without hardcoding kernel version ranges, which is against this tool's design principles. As the tool author noted: "it's going to be almost impossible to detect it on a running kernel."

## CVE-2020-12965 — Transient Execution of Non-Canonical Accesses (SLAM)

- **Issue:** [#478](https://github.com/speed47/spectre-meltdown-checker/issues/478)
- **Bulletin:** [AMD-SB-1010](https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1010)
- **Research paper:** [SLAM (VUSec)](https://www.vusec.net/projects/slam/)
- **CVSS:** 7.5 (High)

AMD CPUs may transiently execute non-canonical loads and stores using only the lower 48 address bits, potentially resulting in data leakage. The SLAM research (2023) demonstrated that this could be exploited on existing AMD Zen+/Zen2 CPUs and could also affect future CPUs with Intel LAM, AMD UAI, or ARM TBI features.

**Why out of scope:** AMD's mitigation guidance is for software vendors to "analyze their code for any potential vulnerabilities" and insert LFENCE or use existing speculation mitigation techniques in their own code. No microcode or kernel-level mitigations have been issued. The responsibility falls on individual software, not on the kernel or firmware, leaving nothing for this script to check.

## CVE-2024-36348 — AMD Transient Scheduler Attack (UMIP bypass)

- **Bulletin:** [AMD-SB-7029](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7029.html)
- **CVSS:** 3.8 (Low)

A transient execution vulnerability in some AMD processors may allow a user process to speculatively infer CPU configuration registers even when UMIP is enabled.

**Why out of scope:** AMD has determined that "leakage of CPU Configuration does not result in leakage of sensitive information" and has marked this CVE as "No fix planned" across all affected product lines. No microcode or kernel mitigations have been issued, leaving nothing for this script to check.

## CVE-2024-36349 — AMD Transient Scheduler Attack (TSC_AUX leak)

- **Bulletin:** [AMD-SB-7029](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7029.html)
- **CVSS:** 3.8 (Low)

A transient execution vulnerability in some AMD processors may allow a user process to infer TSC_AUX even when such a read is disabled.

**Why out of scope:** AMD has determined that "leakage of TSC_AUX does not result in leakage of sensitive information" and has marked this CVE as "No fix planned" across all affected product lines. No microcode or kernel mitigations have been issued, leaving nothing for this script to check.
