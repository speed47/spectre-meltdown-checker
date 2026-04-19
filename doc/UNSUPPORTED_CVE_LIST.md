# Unsupported CVEs

This document lists transient execution CVEs that have been evaluated and determined to be **out of scope** for this tool. See the [Which rules are governing the support of a CVE in this tool?](dist/FAQ.md#which-rules-are-governing-the-support-of-a-cve-in-this-tool) section in the FAQ for the general policy.

CVEs are grouped by reason for exclusion:

- [Already covered by an existing CVE check](#already-covered-by-an-existing-cve-check) — subvariants or subsets whose mitigations are already detected under a parent CVE.
- [No kernel or microcode mitigations to check](#no-kernel-or-microcode-mitigations-to-check) — no fix has been issued, or the mitigation is not detectable by this tool.
- [Not a transient/speculative execution vulnerability](#not-a-transientspeculative-execution-vulnerability) — wrong vulnerability class entirely.

---

# Already covered by an existing CVE check

These CVEs are subvariants or subsets of vulnerabilities already implemented in the tool. Their mitigations are detected as part of the parent CVE's checks.

## CVE-2018-3693 — Bounds Check Bypass Store (Spectre v1.1)

- **Issue:** [#236](https://github.com/speed47/spectre-meltdown-checker/issues/236)
- **Red Hat advisory:** [Speculative Store Bypass / Bounds Check Bypass (CVE-2018-3693)](https://access.redhat.com/solutions/3523601)
- **CVSS:** 5.6 (Medium)
- **Covered by:** CVE-2017-5753 (Spectre V1)

A subvariant of Spectre V1 where speculative store operations can write beyond validated buffer boundaries before the bounds check resolves, allowing an attacker to alter cache state and leak information via side channels.

**Why out of scope:** The mitigations are identical to CVE-2017-5753 (Spectre V1): `lfence` instructions after bounds checks and `array_index_nospec()` barriers in kernel code. There is no separate sysfs entry, no new CPU feature flag, and no distinct microcode change. This tool's existing CVE-2017-5753 checks already detect these mitigations (`__user pointer sanitization`, `usercopy/swapgs barriers`), so CVE-2018-3693 is fully covered as part of Spectre V1.

## CVE-2018-15572 — SpectreRSB (Return Stack Buffer)

- **Issue:** [#224](https://github.com/speed47/spectre-meltdown-checker/issues/224)
- **Research paper:** [Spectre Returns! Speculation Attacks using the Return Stack Buffer (WOOT'18)](https://arxiv.org/abs/1807.07940)
- **Kernel fix:** [commit fdf82a7856b3](https://github.com/torvalds/linux/commit/fdf82a7856b32d905c39afc85e34364491e46346) (Linux 4.18.1)
- **CVSS:** 6.5 (Medium)
- **Covered by:** CVE-2017-5715 (Spectre V2)

The `spectre_v2_select_mitigation` function in the Linux kernel before 4.18.1 did not always fill the RSB upon a context switch, allowing userspace-to-userspace SpectreRSB attacks on Skylake+ CPUs where an empty RSB falls back to the BTB.

**Why out of scope:** This CVE is a Spectre V2 mitigation gap (missing RSB filling on context switch), not a distinct hardware vulnerability. It is already fully covered by this tool's CVE-2017-5715 (Spectre V2) checks, which detect whether the kernel performs RSB filling on CPUs vulnerable to RSB underflow (Skylake+ and RSBA-capable CPUs). A missing RSB fill is flagged as a caveat ("RSB filling missing on Skylake+") in the Spectre V2 verdict.

## CVE-2019-1125 — Spectre SWAPGS gadget

- **Issue:** [#301](https://github.com/speed47/spectre-meltdown-checker/issues/301)
- **Kernel fix:** [commit 18ec54fdd6d1](https://github.com/torvalds/linux/commit/18ec54fdd6d18d92025af097cd042a75cf0ea24c) (Linux 5.3)
- **CVSS:** 5.6 (Medium)
- **Covered by:** CVE-2017-5753 (Spectre V1)

A Spectre V1 subvariant where the `SWAPGS` instruction can be speculatively executed on x86 CPUs, allowing an attacker to leak kernel memory via a side channel on the GS segment base value.

**Why out of scope:** This is a Spectre V1 subvariant whose mitigation (SWAPGS barriers) shares the same sysfs entry as CVE-2017-5753. This tool's existing CVE-2017-5753 checks already detect SWAPGS barriers: a mitigated kernel reports `"Mitigation: usercopy/swapgs barriers and __user pointer sanitization"`, while a kernel lacking the fix reports `"Vulnerable: __user pointer sanitization and usercopy barriers only; no swapgs barriers"`. CVE-2019-1125 is therefore fully covered as part of Spectre V1.

## CVE-2021-26341 — AMD Straight-Line Speculation (direct branches)

- **Bulletin:** [AMD-SB-1026](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-1026.html)
- **Affected CPUs:** AMD Zen 1, Zen 2
- **CVSS:** 6.5 (Medium)
- **Covered by:** CVE-0000-0001 (SLS supplementary check)

AMD Zen 1/Zen 2 CPUs may transiently execute instructions beyond unconditional direct branches (JMP, CALL), potentially allowing information disclosure via side channels.

**Why out of scope:** This is the AMD-specific direct-branch subset of the broader Straight-Line Speculation (SLS) class. The kernel mitigates it via `CONFIG_MITIGATION_SLS` (formerly `CONFIG_SLS`), which enables the GCC flag `-mharden-sls=all` to insert INT3 after unconditional control flow instructions. Since this is a compile-time-only mitigation with no sysfs interface, no MSR, and no per-CVE CPU feature flag, it cannot be checked using the standard CVE framework. A supplementary SLS check is available via `--extra` mode, which covers this CVE's mitigation as well.

## CVE-2020-13844 — ARM Straight-Line Speculation

- **Advisory:** [ARM Developer Security Update (June 2020)](https://developer.arm.com/Arm%20Security%20Center/Speculative%20Processor%20Vulnerability)
- **Affected CPUs:** Cortex-A32, A34, A35, A53, A57, A72, A73, and broadly all speculative Armv8-A cores
- **CVSS:** 5.5 (Medium)
- **Covered by:** CVE-0000-0001 (SLS supplementary check)

ARM processors may speculatively execute instructions past unconditional control flow changes (RET, BR, BLR). GCC and Clang support `-mharden-sls=all` for aarch64, but the Linux kernel never merged the patches to enable it: a `CONFIG_HARDEN_SLS_ALL` series was submitted in 2021 but rejected upstream.

**Why out of scope:** This is the ARM-specific subset of the broader Straight-Line Speculation (SLS) class. The supplementary SLS check available via `--extra` mode detects affected ARM CPU models and reports that no kernel mitigation is currently available.

## CVE-2024-2201 — Native BHI (Branch History Injection without eBPF)

- **Issue:** [#491](https://github.com/speed47/spectre-meltdown-checker/issues/491)
- **Research:** [InSpectre Gadget / Native BHI (VUSec)](https://www.vusec.net/projects/native-bhi/)
- **Intel advisory:** [Branch History Injection (Intel)](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/branch-history-injection.html)
- **Affected CPUs:** Intel CPUs with eIBRS (Ice Lake+, 10th gen+, and virtualized Intel guests)
- **CVSS:** 4.7 (Medium)
- **Covered by:** CVE-2017-5715 (Spectre V2)

VUSec researchers demonstrated that the original BHI mitigation (disabling unprivileged eBPF) was insufficient: 1,511 native kernel gadgets exist that allow exploiting Branch History Injection without eBPF, leaking arbitrary kernel memory at ~3.5 kB/sec on Intel CPUs.

**Why out of scope:** CVE-2024-2201 is not a new hardware vulnerability — it is the same BHI hardware bug as CVE-2022-0002, but proves that eBPF restriction alone was never sufficient. The required mitigations are identical: `BHI_DIS_S` hardware control (MSR `IA32_SPEC_CTRL` bit 10), software BHB clearing loop at syscall entry and VM exit, or retpoline with RRSBA disabled. These are all already detected by this tool's CVE-2017-5715 (Spectre V2) checks, which parse the `BHI:` suffix from `/sys/devices/system/cpu/vulnerabilities/spectre_v2` and check for `CONFIG_MITIGATION_SPECTRE_BHI` in no-runtime mode. No new sysfs entry, MSR, kernel config option, or boot parameter was introduced for this CVE.

## CVE-2020-0549 — L1D Eviction Sampling (CacheOut)

- **Issue:** [#341](https://github.com/speed47/spectre-meltdown-checker/issues/341)
- **Advisory:** [INTEL-SA-00329](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/l1d-eviction-sampling.html)
- **Affected CPUs:** Intel Skylake through 10th gen (Tiger Lake+ not affected)
- **CVSS:** 6.5 (Medium)
- **Covered by:** CVE-2018-12126 / CVE-2018-12127 / CVE-2018-12130 / CVE-2019-11091 (MDS) and CVE-2018-3646 (L1TF)

An Intel-specific data leakage vulnerability where L1 data cache evictions can be exploited in combination with MDS or TAA side channels to leak data across security boundaries.

**Why out of scope:** The June 2020 microcode update that addresses this CVE does not introduce any new MSR bits or CPUID flags — it reuses the existing MD_CLEAR (`CPUID.7.0:EDX[10]`) and L1D_FLUSH (`MSR_IA32_FLUSH_CMD`, 0x10B) infrastructure already deployed for MDS and L1TF. The Linux kernel has no dedicated sysfs entry in `/sys/devices/system/cpu/vulnerabilities/` for this CVE; instead, it provides an opt-in per-task L1D flush via `prctl(PR_SPEC_L1D_FLUSH)` and the `l1d_flush=on` boot parameter, which piggyback on the same L1D flush mechanism checked by the existing L1TF and MDS vulnerability modules. In practice, a system with up-to-date microcode and MDS/L1TF mitigations in place is already protected against L1D Eviction Sampling.

## CVE-2025-20623 — Shared Microarchitectural Predictor State (10th Gen Intel)

- **Advisory:** [INTEL-SA-01247](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01247.html)
- **Affected CPUs:** Intel 10th Generation Core Processors only
- **CVSS:** 5.6 (Medium)
- **Covered by:** CVE-2024-45332 (BPI)

Shared microarchitectural predictor state on 10th generation Intel CPUs may allow information disclosure.

**Why out of scope:** Very narrow scope (single CPU generation). Mitigated by the same microcode update as CVE-2024-45332 (BPI) and handled through the existing Spectre V2 framework. No dedicated sysfs entry or kernel mitigation beyond what BPI already provides.

## CVE-2025-24495 — Lion Cove BPU Initialization

- **Advisory:** [INTEL-SA-01322](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01322.html)
- **Research:** [Training Solo (VUSec)](https://www.vusec.net/projects/training-solo/)
- **Affected CPUs:** Intel Core Ultra with Lion Cove core only (Lunar Lake, Arrow Lake)
- **CVSS:** 6.8 (Medium, CVSS v4)
- **Covered by:** CVE-2024-28956 (ITS)

A branch predictor initialization issue specific to Intel's Lion Cove microarchitecture, discovered as part of the "Training Solo" research.

**Why out of scope:** This is a subset of the ITS (Indirect Target Selection) vulnerability (CVE-2024-28956). It shares the same sysfs entry (`/sys/devices/system/cpu/vulnerabilities/indirect_target_selection`) and kernel mitigation framework. Since ITS (CVE-2024-28956) is implemented in this tool, Lion Cove BPU is already covered automatically.

---

# No kernel or microcode mitigations to check

These CVEs are real vulnerabilities, but no kernel or microcode fix has been issued, the mitigation is delegated to individual software, or the fix is not detectable by this tool.

## CVE-2018-3665 — Lazy FP State Restore (LazyFP)

- **Advisory:** [INTEL-SA-00145](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/lazy-fp-state-restore.html)
- **Research paper:** [LazyFP: Leaking FPU Register State using Microarchitectural Side-Channels (Stecklina & Prescher, 2018)](https://arxiv.org/abs/1806.07480)
- **Affected CPUs:** Intel Core family (Sandy Bridge through Kaby Lake) when lazy FPU switching is in use
- **CVSS:** 4.3 (Medium)

Intel CPUs using lazy FPU state switching may speculatively expose another process's FPU/SSE/AVX register contents (including AES round keys and other cryptographic material) across context switches. The `#NM` (device-not-available) exception normally used to trigger lazy restore is delivered late enough that dependent instructions can transiently execute against the stale FPU state before the fault squashes them.

**Why out of scope:** The Linux mitigation is to use eager FPU save/restore, which was already the default on Intel CPUs with XSAVEOPT well before disclosure, and was then hard-enforced upstream by the removal of all lazy FPU code in Linux 4.14 (Andy Lutomirski's "x86/fpu: Hard-disable lazy FPU mode" cleanup). There is no `/sys/devices/system/cpu/vulnerabilities/` entry, no CPUID flag, no MSR, and no kernel config option that reflects this mitigation — detection on a running kernel would require hardcoding kernel version ranges, which is against this tool's design principles (same rationale as CVE-2019-15902). In practice, any supported kernel today is eager-FPU-only, and CPUs advertising XSAVEOPT/XSAVES cannot enter the vulnerable lazy-switching mode regardless of kernel configuration.

## CVE-2018-9056 — BranchScope

- **Issue:** [#169](https://github.com/speed47/spectre-meltdown-checker/issues/169)
- **Research paper:** [BranchScope (ASPLOS 2018)](http://www.cs.ucr.edu/~nael/pubs/asplos18.pdf)
- **Red Hat bug:** [#1561794](https://bugzilla.redhat.com/show_bug.cgi?id=1561794)
- **CVSS:** 5.6 (Medium)

A speculative execution attack exploiting the directional branch predictor, allowing an attacker to infer data by manipulating the shared branch prediction state (pattern history table). Initially demonstrated on Intel processors.

**Why out of scope:** No kernel or microcode mitigations have been issued. Red Hat closed their tracking bug as "CLOSED CANTFIX", concluding that "this is a hardware processor issue, not a Linux kernel flaw" and that "it is specific to a target software which uses sensitive information in branching expressions." The mitigation responsibility falls on individual software to avoid using sensitive data in conditional branches, which is out of the scope of this tool.

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

## CVE-2020-24511 — Domain-Type Confusion (IBRS Scope)

- **Issue:** [#409](https://github.com/speed47/spectre-meltdown-checker/issues/409)
- **Advisory:** [INTEL-SA-00464](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00464.html)
- **Affected CPUs:** Intel Skylake through Comet Lake (different steppings; see advisory for details)
- **CVSS:** 6.5 (Medium)

Improper isolation of shared resources in some Intel processors allows an authenticated user to potentially enable information disclosure via local access. Specifically, the Indirect Branch Restricted Speculation (IBRS) mitigation may not be fully applied after certain privilege-level transitions, allowing residual branch predictions to cross security boundaries.

**Why out of scope:** The mitigation is exclusively a microcode update (released June 2021) with no corresponding Linux kernel sysfs entry in `/sys/devices/system/cpu/vulnerabilities/`, no new CPUID bit, no new MSR, and no kernel configuration option. The only way to detect the fix would be to maintain a per-CPU-stepping minimum microcode version lookup table, which is brittle and high-maintenance. Additionally, Intel dropped microcode support for Sandy Bridge and Ivy Bridge in the same timeframe, leaving those generations permanently unpatched with no mitigation path available.

## CVE-2020-24512 — Observable Timing Discrepancy (Trivial Data Value)

- **Issue:** [#409](https://github.com/speed47/spectre-meltdown-checker/issues/409)
- **Advisory:** [INTEL-SA-00464](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00464.html)
- **Affected CPUs:** Intel Skylake through Tiger Lake (broad scope; see advisory for details)
- **CVSS:** 2.8 (Low)

Observable timing discrepancy in some Intel processors allows an authenticated user to potentially enable information disclosure via local access. Certain cache optimizations treat "trivial data value" cache lines (e.g., all-zero lines) differently from non-trivial lines, creating a timing side channel that can distinguish memory content patterns.

**Why out of scope:** Like CVE-2020-24511, this is a microcode-only fix with no Linux kernel sysfs entry, no CPUID bit, no MSR, and no kernel configuration option. Detection would require a per-CPU-stepping microcode version lookup table. The vulnerability has low severity (CVSS 2.8) and practical exploitation is limited. Intel dropped microcode support for Sandy Bridge and Ivy Bridge, leaving those generations permanently vulnerable.

## CVE-2021-26318 — AMD Prefetch Attacks through Power and Time

- **Issue:** [#412](https://github.com/speed47/spectre-meltdown-checker/issues/412)
- **Bulletin:** [AMD-SB-1017](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-1017.html)
- **Research paper:** [AMD Prefetch Attacks through Power and Time (USENIX Security '22)](https://www.usenix.org/conference/usenixsecurity22/presentation/lipp)
- **CVSS:** 5.5 (Medium)

The x86 PREFETCH instruction on AMD CPUs leaks timing and power information, enabling a microarchitectural KASLR bypass from unprivileged userspace. The researchers demonstrated kernel address space layout recovery and kernel memory leakage at ~52 B/s using Spectre gadgets.

**Why out of scope:** AMD acknowledged the research but explicitly stated they are "not recommending any mitigations at this time," as the attack leaks kernel address layout information (KASLR bypass) but does not directly leak kernel data across address space boundaries. KPTI was never enabled on AMD by default in the Linux kernel as a result. No microcode, kernel, or sysfs mitigations have been issued, leaving nothing for this script to check.

## CVE-2024-7881 — ARM Prefetcher Privilege Escalation

- **Affected CPUs:** Specific ARM cores only
- **CVSS:** 5.1 (Medium)

The prefetch engine on certain ARM cores can fetch data from privileged memory locations. Mitigation is disabling the affected prefetcher via the `CPUACTLR6_EL1[41]` register bit.

**Why out of scope:** ARM-specific with very narrow scope and no Linux sysfs integration. The mitigation is a per-core register tweak, not a kernel or microcode update detectable by this tool.

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

## No CVE — BlindSide (Speculative Probing)

- **Issue:** [#374](https://github.com/speed47/spectre-meltdown-checker/issues/374)
- **Research paper:** [Speculative Probing: Hacking Blind in the Spectre Era (VUSec, ACM CCS 2020)](https://www.vusec.net/projects/blindside/)
- **Red Hat advisory:** [Article 5394291](https://access.redhat.com/articles/5394291)
- **Affected CPUs:** All CPUs vulnerable to Spectre V2 (BTB-based speculative execution)

An attack technique that combines a pre-existing kernel memory corruption bug (e.g., a heap buffer overflow) with speculative execution to perform "Speculative BROP" (Blind Return-Oriented Programming). Instead of crashing the system when probing invalid addresses, BlindSide performs the probing speculatively: faults are suppressed in the speculative domain, and information is leaked via cache timing side channels. This allows an attacker to silently derandomize kernel memory layout and bypass KASLR/FGKASLR without triggering any fault.

**Why out of scope:** BlindSide is an exploitation technique, not a discrete hardware vulnerability: no CVE was assigned. Red Hat explicitly states it is "not a new flaw, but a new attack." It requires a pre-existing kernel memory corruption bug as a prerequisite, and the speculative execution aspect leverages the same BTB behavior as Spectre V2 (CVE-2017-5715). No dedicated microcode update, kernel config, MSR, CPUID bit, or sysfs entry exists for BlindSide. The closest hardware mitigations (IBPB, IBRS, STIBP, Retpoline) are already covered by this tool's Spectre V2 checks.

## No CVE — TLBleed (TLB side-channel)

- **Issue:** [#231](https://github.com/speed47/spectre-meltdown-checker/issues/231)
- **Research paper:** [Defeating Cache Side-channel Protections with TLB Attacks (VUSec, USENIX Security '18)](https://www.vusec.net/projects/tlbleed/)
- **Red Hat blog:** [Temporal side-channels and you: Understanding TLBleed](https://www.redhat.com/en/blog/temporal-side-channels-and-you-understanding-tlbleed)
- **Affected CPUs:** Intel CPUs with Hyper-Threading (demonstrated on Skylake, Coffee Lake, Broadwell Xeon)

A timing side-channel attack exploiting the shared Translation Lookaside Buffer (TLB) on Intel hyperthreaded CPUs. By using machine learning to analyze TLB hit/miss timing patterns, an attacker co-located on the same physical core can extract cryptographic keys (demonstrated with 99.8% success rate on a 256-bit EdDSA key). OpenBSD disabled Hyper-Threading by default in response.

**Why out of scope:** No CVE was ever assigned — Intel explicitly declined to request one. Intel stated the attack is "not related to Spectre or Meltdown" and has no plans to issue a microcode fix, pointing to existing constant-time coding practices in cryptographic software as the appropriate defense. No Linux kernel mitigation was ever merged. Red Hat's guidance was limited to operational advice (disable SMT, use CPU pinning) rather than a software fix. The only OS-level response was OpenBSD disabling Hyper-Threading by default. With no CVE, no microcode update, and no kernel mitigation, there is nothing for this script to check.

---

# Not a transient/speculative execution vulnerability

These are hardware flaws but not side-channel or speculative execution issues. They fall outside the vulnerability class this tool is designed to detect.

## CVE-2019-11157 — Plundervolt (VoltJockey)

- **Issue:** [#335](https://github.com/speed47/spectre-meltdown-checker/issues/335)
- **Advisory:** [INTEL-SA-00289](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00289.html)
- **Research:** [Plundervolt (plundervolt.com)](https://plundervolt.com/)
- **Affected CPUs:** Intel Core 6th–10th gen (Skylake through Comet Lake) with SGX
- **CVSS:** 7.1 (High)

A voltage fault injection attack where a privileged attacker (ring 0) uses the software-accessible voltage scaling interface to undervolt the CPU during SGX enclave computations, inducing predictable bit flips that compromise enclave integrity and confidentiality. Intel's microcode fix locks down the voltage/frequency scaling MSRs to prevent software-initiated undervolting.

**Why out of scope:** Not a transient or speculative execution vulnerability — this is a fault injection attack exploiting voltage manipulation, with no side-channel or speculative execution component. It requires ring 0 access and targets SGX enclaves specifically. While Intel issued a microcode update that locks voltage controls, there is no Linux kernel sysfs entry, no CPUID flag, and no kernel-side mitigation to detect. The fix is purely a microcode-level lockdown of voltage scaling registers, which is not exposed in any standard interface this tool can query.

## CVE-2020-8694 / CVE-2020-8695 — Platypus (RAPL Power Side Channel)

- **Issue:** [#384](https://github.com/speed47/spectre-meltdown-checker/issues/384)
- **Advisory:** [INTEL-SA-00389](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00389.html)
- **Research:** [PLATYPUS (platypusattack.com)](https://platypusattack.com/)
- **Affected CPUs:** Intel Core (Sandy Bridge+), Intel Xeon (Sandy Bridge-EP+)
- **CVSS:** 5.6 (Medium) / 6.5 (Medium)

A software-based power side-channel attack exploiting Intel's Running Average Power Limit (RAPL) interface. By monitoring energy consumption reported through the `powercap` sysfs interface or the `MSR_RAPL_POWER_UNIT` / `MSR_PKG_ENERGY_STATUS` MSRs, an unprivileged attacker can statistically distinguish instructions and operands, recover AES-NI keys from SGX enclaves, and break kernel ASLR.

**Why out of scope:** Not a transient or speculative execution vulnerability — this is a power analysis side-channel attack with no speculative execution component. The mitigations (microcode update restricting RAPL energy reporting to privileged access, and kernel restricting the `powercap` sysfs interface) are not exposed via `/sys/devices/system/cpu/vulnerabilities/`. There is no dedicated sysfs vulnerability entry, no CPUID flag, and no kernel configuration option for this tool to check.

## CVE-2023-31315 — SinkClose (AMD SMM Lock Bypass)

- **Issue:** [#499](https://github.com/speed47/spectre-meltdown-checker/issues/499)
- **Bulletin:** [AMD-SB-7014](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html)
- **Research:** [AMD SinkClose (IOActive, DEF CON 32)](https://www.ioactive.com/resources/amd-sinkclose-universal-ring-2-privilege-escalation)
- **Affected CPUs:** AMD Zen 1–5 (EPYC, Ryzen, Threadripper, Embedded)
- **CVSS:** 7.5 (High)

Improper validation in a model-specific register (MSR) allows a program with ring 0 (kernel) access to modify System Management Mode (SMM) configuration while SMI lock is enabled, escalating privileges from ring 0 to ring -2 (SMM). AMD provides two mitigation paths: BIOS/AGESA firmware updates (all product lines) and hot-loadable microcode updates (EPYC server processors only).

**Why out of scope:** Not a transient or speculative execution vulnerability — this is a privilege escalation via MSR manipulation, with no side-channel component. It requires ring 0 access as a prerequisite, fundamentally different from Spectre/Meltdown-class attacks where unprivileged code can leak data across privilege boundaries. There is no Linux kernel sysfs entry and no kernel-side mitigation. Although AMD provides hot-loadable microcode for some EPYC processors, the client and embedded product lines are mitigated only through BIOS firmware updates, which this tool cannot detect.

## CVE-2024-56161 — EntrySign (AMD Microcode Signature Bypass)

- **Affected CPUs:** AMD Zen 1-5
- **CVSS:** 7.2 (High)

A weakness in AMD's microcode signature verification (AES-CMAC hash) allows loading arbitrary unsigned microcode with administrator privileges.

**Why out of scope:** This is a microcode integrity/authentication issue, not a speculative execution vulnerability. It does not involve transient execution side channels and is outside the scope of this tool.

## CVE-2025-29943 — StackWarp (AMD SEV-SNP)

- **Affected CPUs:** AMD Zen 1-5
- **CVSS:** Low

Exploits a synchronization failure in the AMD stack engine via an undocumented MSR bit, targeting AMD SEV-SNP confidential VMs. Requires hypervisor-level (ring 0) access.

**Why out of scope:** Not a transient/speculative execution side channel. This is an architectural attack on AMD SEV-SNP confidential computing that requires hypervisor access, which is outside the threat model of this tool.
