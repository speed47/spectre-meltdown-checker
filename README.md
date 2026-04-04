Spectre & Meltdown Checker
==========================

A self-contained shell script to assess your system's resilience against the several [transient execution](https://en.wikipedia.org/wiki/Transient_execution_CPU_vulnerability) CVEs that were published since early 2018, and give you guidance as to how to mitigate them.

## CVE list

CVE | Name | Aliases
--- | ---- | -------
[CVE-2017-5753](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5753) | Bounds Check Bypass | Spectre V1
[CVE-2017-5715](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715) | Branch Target Injection | Spectre V2
[CVE-2017-5754](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754) | Rogue Data Cache Load | Meltdown
[CVE-2018-3640](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3640) | Rogue System Register Read | Variant 3a
[CVE-2018-3639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639) | Speculative Store Bypass | Variant 4, SSB
[CVE-2018-3615](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3615) | L1 Terminal Fault | Foreshadow (SGX)
[CVE-2018-3620](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3620) | L1 Terminal Fault | Foreshadow-NG (OS/SMM)
[CVE-2018-3646](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3646) | L1 Terminal Fault | Foreshadow-NG (VMM)
[CVE-2018-12126](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12126) | Microarchitectural Store Buffer Data Sampling | MSBDS, Fallout
[CVE-2018-12127](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12127) | Microarchitectural Load Port Data Sampling | MLPDS, RIDL
[CVE-2018-12130](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12130) | Microarchitectural Fill Buffer Data Sampling | MFBDS, ZombieLoad
[CVE-2018-12207](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12207) | Machine Check Exception on Page Size Changes | iTLB Multihit, No eXcuses
[CVE-2019-11091](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11091) | Microarchitectural Data Sampling Uncacheable Memory | MDSUM, RIDL
[CVE-2019-11135](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11135) | TSX Asynchronous Abort | TAA, ZombieLoad V2
[CVE-2020-0543](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0543) | Special Register Buffer Data Sampling | SRBDS, CROSSTalk
[CVE-2022-29900](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29900) | Arbitrary Speculative Code Execution with Return Instructions | Retbleed (AMD)
[CVE-2022-29901](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-29901) | Arbitrary Speculative Code Execution with Return Instructions | Retbleed (Intel), RSBA
[CVE-2022-40982](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40982) | Gather Data Sampling | Downfall, GDS
[CVE-2023-20569](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20569) | Return Address Security | Inception, SRSO
[CVE-2023-20593](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20593) | Cross-Process Information Leak | Zenbleed
[CVE-2023-23583](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23583) | Redundant Prefix Issue | Reptar
[CVE-2024-28956](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28956) | Indirect Target Selection | ITS
[CVE-2024-36350](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36350) | Transient Scheduler Attack, Store Queue | TSA-SQ
[CVE-2024-36357](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-36357) | Transient Scheduler Attack, L1 | TSA-L1
[CVE-2025-40300](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-40300) | VM-Exit Stale Branch Prediction | VMScape
[CVE-2024-45332](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-45332) | Branch Privilege Injection | BPI

## Am I at risk?

Depending on your situation, the table below answers whether an attacker in a given position can extract data from a given target.
The "Userland → Kernel" column also applies within a VM (VM userland vs. VM kernel), since the same CPU mechanisms are at play regardless of virtualization.

Vulnerability | Userland → Kernel | Userland → Userland | VM → Host | VM → VM | Mitigation
------------ | :---------------: | :-----------------: | :-------: | :-----: | ----------
CVE-2017-5753 (Spectre V1) | 💥 | 💥 | 💥 | 💥 | Recompile everything with LFENCE
CVE-2017-5715 (Spectre V2) | 💥 | 💥 | 💥 | 💥 | Microcode + kernel update (or retpoline)
CVE-2017-5754 (Meltdown) | 💥 | ✅ | ✅ | ✅ | Kernel update
CVE-2018-3640 (Variant 3a) | 💥 | ✅ | ✅ | ✅ | Microcode update
CVE-2018-3639 (Variant 4, SSB) | ✅ | 💥 | ✅ | ✅ | Microcode + kernel update
CVE-2018-3615 (Foreshadow, SGX) | ✅ (3) | ✅ (3) | ✅ (3) | ✅ (3) | Microcode update
CVE-2018-3620 (Foreshadow-NG, OS/SMM) | 💥 | ✅ | ✅ | ✅ | Kernel update
CVE-2018-3646 (Foreshadow-NG, VMM) | ✅ | ✅ | 💥 | 💥 | Kernel update (or disable EPT/SMT)
CVE-2018-12126 (MSBDS, Fallout) | 💥 | 💥 (1) | 💥 | 💥 (1) | Microcode + kernel update
CVE-2018-12127 (MLPDS, RIDL) | 💥 | 💥 (1) | 💥 | 💥 (1) | Microcode + kernel update
CVE-2018-12130 (MFBDS, ZombieLoad) | 💥 | 💥 (1) | 💥 | 💥 (1) | Microcode + kernel update
CVE-2018-12207 (iTLB Multihit, No eXcuses) | ✅ | ✅ | ☠️ | ✅ | Hypervisor update (or disable hugepages)
CVE-2019-11091 (MDSUM, RIDL) | 💥 | 💥 (1) | 💥 | 💥 (1) | Microcode + kernel update
CVE-2019-11135 (TAA, ZombieLoad V2) | 💥 | 💥 (1) | 💥 | 💥 (1) | Microcode + kernel update
CVE-2020-0543 (SRBDS, CROSSTalk) | 💥 (2) | 💥 (2) | 💥 (2) | 💥 (2) | Microcode + kernel update
CVE-2022-29900 (Retbleed AMD) | 💥 | ✅ | 💥 | ✅ | Kernel update (+ microcode for IBPB)
CVE-2022-29901 (Retbleed Intel, RSBA) | 💥 | ✅ | 💥 | ✅ | Microcode + kernel update (eIBRS or IBRS)
CVE-2022-40982 (Downfall, GDS) | 💥 | 💥 | 💥 | 💥 | Microcode update (or disable AVX)
CVE-2023-20569 (Inception, SRSO) | 💥 | ✅ | 💥 | ✅ | Microcode + kernel update
CVE-2023-20593 (Zenbleed) | 💥 | 💥 | 💥 | 💥 | Microcode update (or kernel workaround)
CVE-2023-23583 (Reptar) | ☠️ | ☠️ | ☠️ | ☠️ | Microcode update
CVE-2024-28956 (ITS) | 💥 | ✅ | 💥 (4) | ✅ | Microcode + kernel update
CVE-2024-36350 (TSA-SQ) | 💥 | 💥 (1) | 💥 | 💥 (1) | Microcode + kernel update
CVE-2024-36357 (TSA-L1) | 💥 | 💥 (1) | 💥 | 💥 (1) | Microcode + kernel update
CVE-2025-40300 (VMScape) | ✅ | ✅ | 💥 | ✅ | Kernel update (IBPB on VM-exit)
CVE-2024-45332 (BPI) | 💥 | ✅ | 💥 | ✅ | Microcode update

> 💥 Data can be leaked across this boundary.

> ✅ Not affected in this scenario.

> ☠️ Denial of service (system crash or unpredictable behavior), no data leak.

> (1) Cross-process leakage requires SMT (Hyper-Threading) to be active — attacker and victim must share a physical core.

> (2) Only leaks RDRAND/RDSEED output, not arbitrary memory; still allows recovering cryptographic material from any victim.

> (3) CVE-2018-3615 (Foreshadow SGX) inverts the normal trust model: the OS reads SGX enclave data. It is irrelevant unless the system runs SGX enclaves, and the attacker must already have OS-level access.

> (4) VM→Host leakage applies only to certain affected CPU models (Skylake-X, Kaby Lake, Comet Lake). Ice Lake, Tiger Lake, and Rocket Lake are only affected for native (user-to-kernel) attacks, not guest-to-host.

## Detailed CVE descriptions

<details>
<summary>Unfold for more detailed CVE descriptions</summary>

**CVE-2017-5753 — Bounds Check Bypass (Spectre Variant 1)**

An attacker can train the branch predictor to mispredict a bounds check, causing the CPU to speculatively access out-of-bounds memory. This affects all software, including the kernel, because any conditional bounds check can potentially be exploited. Mitigation requires recompiling software and the kernel with a compiler that inserts LFENCE instructions (or equivalent speculation barriers like `array_index_nospec`) at the proper positions. The performance impact is negligible because the barriers only apply to specific, targeted code patterns.

**CVE-2017-5715 — Branch Target Injection (Spectre Variant 2)**

An attacker can poison the Branch Target Buffer (BTB) to redirect speculative execution of indirect branches in the kernel, leaking kernel memory. Two mitigation strategies exist: (1) microcode updates providing IBRS (Indirect Branch Restricted Speculation), which flushes branch predictor state on privilege transitions — this has a medium to high performance cost, especially on older hardware; or (2) retpoline, a compiler technique that replaces indirect branches with a construct the speculator cannot exploit — this has a lower performance cost but requires recompiling the kernel and sensitive software.

**CVE-2017-5754 — Rogue Data Cache Load (Meltdown)**

On affected Intel processors, a user process can speculatively read kernel memory despite lacking permission. The CPU eventually raises a fault, but the data leaves observable traces in the cache. Mitigation is entirely kernel-side: Page Table Isolation (PTI/KPTI) unmaps most kernel memory from user-space page tables, so there is nothing to speculatively read. The performance impact is low to medium, mainly from the increased TLB pressure caused by switching page tables on every kernel entry and exit.

**CVE-2018-3640 — Rogue System Register Read (Variant 3a)**

Similar to Meltdown but targeting system registers: an unprivileged process can speculatively read privileged system register values (such as Model-Specific Registers) and exfiltrate them via a side channel. Mitigation requires a microcode update only — no kernel changes are needed. Performance impact is negligible.

**CVE-2018-3639 — Speculative Store Bypass (Variant 4)**

The CPU may speculatively load a value from memory before a preceding store to the same address completes, reading stale data. This primarily affects software using JIT compilation (e.g. JavaScript engines, eBPF), where an attacker can craft code that exploits the store-to-load dependency. No known exploitation against the kernel itself has been demonstrated. Mitigation requires a microcode update (providing the SSBD mechanism) plus a kernel update that allows affected software to opt in to the protection via prctl(). The performance impact is low to medium, depending on how frequently the mitigation is activated.

**CVE-2018-3615 — L1 Terminal Fault (Foreshadow, SGX)**

The original Foreshadow attack targets Intel SGX enclaves. When a page table entry's Present bit is cleared, the CPU may still speculatively use the physical address in the entry to fetch data from the L1 cache, bypassing SGX protections. An attacker can extract secrets (attestation keys, sealed data) from SGX enclaves. Mitigation requires a microcode update that includes modifications to SGX behavior. Performance impact is negligible.

**CVE-2018-3620 — L1 Terminal Fault (Foreshadow-NG, OS/SMM)**

A generalization of Foreshadow beyond SGX: unprivileged user-space code can exploit the same L1TF mechanism to read kernel memory or System Management Mode (SMM) memory. Mitigation requires a kernel update that implements PTE inversion — marking non-present page table entries with invalid physical addresses so the L1 cache cannot contain useful data at those addresses. Performance impact is negligible because PTE inversion is a one-time change to the page table management logic with no runtime overhead.

**CVE-2018-3646 — L1 Terminal Fault (Foreshadow-NG, VMM)**

A guest VM can exploit L1TF to read memory belonging to the host or other guests, because the hypervisor's page tables may have non-present entries pointing to valid host physical addresses still resident in L1. Mitigation options include: flushing the L1 data cache on every VM entry (via a kernel update providing L1d flush support), disabling Extended Page Tables (EPT), or disabling Hyper-Threading (SMT) to prevent a sibling thread from refilling the L1 cache during speculation. The performance impact ranges from low to significant depending on the chosen mitigation, with L1d flushing on VM entry being the most practical but still measurable on VM-heavy workloads.

**CVE-2018-12126 — Microarchitectural Store Buffer Data Sampling (MSBDS, Fallout)**

**CVE-2018-12127 — Microarchitectural Load Port Data Sampling (MLPDS, RIDL)**

**CVE-2018-12130 — Microarchitectural Fill Buffer Data Sampling (MFBDS, ZombieLoad)**

**CVE-2019-11091 — Microarchitectural Data Sampling Uncacheable Memory (MDSUM, RIDL)**

These four CVEs are collectively known as "MDS" (Microarchitectural Data Sampling) vulnerabilities. They exploit different CPU internal buffers — store buffer, fill buffer, load ports, and uncacheable memory paths — that can leak recently accessed data across privilege boundaries during speculative execution. An unprivileged attacker can observe data recently processed by the kernel or other processes. Mitigation requires a microcode update (providing the MD_CLEAR mechanism) plus a kernel update that uses VERW to clear affected buffers on privilege transitions. Disabling Hyper-Threading (SMT) provides additional protection because sibling threads share these buffers. The performance impact is low to significant, depending on the frequency of kernel transitions and whether SMT is disabled.

**CVE-2018-12207 — Machine Check Exception on Page Size Changes (iTLB Multihit, No eXcuses)**

A malicious guest VM can trigger a machine check exception (MCE) — crashing the entire host — by creating specific conditions in the instruction TLB involving page size changes. This is a denial-of-service vulnerability affecting hypervisors running untrusted guests. Mitigation requires either disabling hugepage use in the hypervisor or updating the hypervisor to avoid the problematic iTLB configurations. The performance impact ranges from low to significant depending on the approach: disabling hugepages can substantially impact memory-intensive workloads.

**CVE-2019-11135 — TSX Asynchronous Abort (TAA, ZombieLoad V2)**

On CPUs with Intel TSX, a transactional abort can leave data from the line fill buffers in a state observable through side channels, similar to the MDS vulnerabilities but triggered through TSX. Mitigation requires a microcode update plus kernel support to either clear affected buffers or disable TSX entirely (via the TSX_CTRL MSR). The performance impact is low to significant, similar to MDS, with the option to eliminate the attack surface entirely by disabling TSX at the cost of losing transactional memory support.

**CVE-2020-0543 — Special Register Buffer Data Sampling (SRBDS, CROSSTalk)**

Certain special CPU instructions (RDRAND, RDSEED, EGETKEY) read data through a shared staging buffer that is accessible across all cores via speculative execution. An attacker running code on any core can observe the output of these instructions from a victim on a different core, including extracting cryptographic keys from SGX enclaves (a complete ECDSA key was demonstrated). This is notable as one of the first cross-core speculative execution attacks. Mitigation requires a microcode update that serializes access to the staging buffer, plus a kernel update to manage the mitigation. Performance impact is low, mainly affecting workloads that heavily use RDRAND/RDSEED.

**CVE-2022-29900 — Arbitrary Speculative Code Execution with Return Instructions (Retbleed AMD)**

On AMD processors from families 0x15 through 0x17 (Bulldozer through Zen 2) and Hygon family 0x18, an attacker can exploit return instructions to redirect speculative execution and leak kernel memory, bypassing retpoline mitigations that were effective against Spectre V2. Unlike Spectre V2 which targets indirect jumps and calls, Retbleed specifically targets return instructions, which were previously considered safe. Mitigation requires a kernel update providing either the untrained return thunk (safe RET) or IBPB-on-entry mechanism, plus a microcode update providing IBPB support on Zen 1/2. On Zen 1/2, SMT should be disabled for full protection when using IBPB-based mitigation. Performance impact is medium.

**CVE-2022-29901 — Arbitrary Speculative Code Execution with Return Instructions (Retbleed Intel, RSBA)**

On Intel Skylake through Rocket Lake processors with RSB Alternate Behavior (RSBA), return instructions can be speculatively redirected via the Branch Target Buffer when the Return Stack Buffer underflows, bypassing retpoline mitigations. Mitigation requires either Enhanced IBRS (eIBRS, via microcode update) or a kernel compiled with IBRS-on-entry support (Linux 5.19+). Call depth tracking (stuffing) is an alternative mitigation available from Linux 6.2+. Plain retpoline does NOT mitigate this vulnerability on RSBA-capable CPUs. Performance impact is medium to high.

**CVE-2022-40982 — Gather Data Sampling (GDS, Downfall)**

The AVX GATHER instructions can leak data from previously used vector registers across privilege boundaries through the shared gather data buffer. This affects any software using AVX2 or AVX-512 on vulnerable Intel processors. Mitigation is provided by a microcode update that clears the gather buffer, or alternatively by disabling the AVX feature entirely. Performance impact is negligible for most workloads but can be significant (up to 50%) for AVX-heavy applications such as HPC and AI inference.

**CVE-2023-20569 — Return Address Security (Inception, SRSO)**

On AMD Zen 1 through Zen 4 processors, an attacker can manipulate the return address predictor to redirect speculative execution on return instructions, leaking kernel memory. Mitigation requires both a kernel update (providing SRSO safe-return sequences or IBPB-on-entry) and a microcode update (providing SBPB on Zen 3/4, or IBPB support on Zen 1/2 — which additionally requires SMT to be disabled). Performance impact ranges from low to significant depending on the chosen mitigation and CPU generation.

**CVE-2023-20593 — Cross-Process Information Leak (Zenbleed)**

A bug in AMD Zen 2 processors causes the VZEROUPPER instruction to incorrectly zero register files during speculative execution, leaving stale data from other processes observable in vector registers. This can leak data across any privilege boundary, including from the kernel and other processes, at rates up to 30 KB/s per core. Mitigation is available either through a microcode update that fixes the bug, or through a kernel workaround that sets the FP_BACKUP_FIX bit (bit 9) in the DE_CFG MSR, disabling the faulty optimization. Either approach alone is sufficient. Performance impact is negligible.

**CVE-2023-23583 — Redundant Prefix Issue (Reptar)**

A bug in Intel processors causes unexpected behavior when executing instructions with specific redundant REX prefixes. Depending on the circumstances, this can result in a system crash (MCE), unpredictable behavior, or potentially privilege escalation. Any software running on an affected CPU can trigger the bug. Mitigation requires a microcode update. Performance impact is low.

**CVE-2024-28956 — Indirect Target Selection (ITS)**

On certain Intel processors (Skylake-X stepping 6+, Kaby Lake, Comet Lake, Ice Lake, Tiger Lake, Rocket Lake), an attacker can train the indirect branch predictor to speculatively execute a targeted gadget in the kernel, bypassing eIBRS protections. The Branch Target Buffer (BTB) uses only partial address bits to index indirect branch targets, allowing user-space code to influence kernel-space speculative execution. Some affected CPUs (Ice Lake, Tiger Lake, Rocket Lake) are only vulnerable to native user-to-kernel attacks, not guest-to-host (VMX) attacks. Mitigation requires both a microcode update (IPU 2025.1 / microcode-20250512+, which fixes IBPB to fully flush indirect branch predictions) and a kernel update (CONFIG_MITIGATION_ITS, Linux 6.15+) that aligns branch/return thunks or uses RSB stuffing. Performance impact is low.

**CVE-2024-36350 — Transient Scheduler Attack, Store Queue (TSA-SQ)**

On AMD Zen 3 and Zen 4 processors, the CPU's transient scheduler may speculatively retrieve stale data from the store queue during certain timing windows, allowing an attacker to infer data from previous store operations across privilege boundaries. The attack can also leak data between SMT sibling threads. Mitigation requires both a microcode update (exposing the VERW_CLEAR capability) and a kernel update (CONFIG_MITIGATION_TSA, Linux 6.16+) that uses the VERW instruction to clear CPU buffers on user/kernel transitions and before VMRUN. The kernel also clears buffers on idle when SMT is active. Performance impact is low to medium.

**CVE-2024-36357 — Transient Scheduler Attack, L1 (TSA-L1)**

On AMD Zen 3 and Zen 4 processors, the CPU's transient scheduler may speculatively retrieve stale data from the L1 data cache during certain timing windows, allowing an attacker to infer data in the L1D cache across privilege boundaries. Mitigation requires the same microcode and kernel updates as TSA-SQ: a microcode update exposing VERW_CLEAR and a kernel update (CONFIG_MITIGATION_TSA, Linux 6.16+) that clears CPU buffers via VERW on privilege transitions. Performance impact is low to medium.

**CVE-2025-40300 — VM-Exit Stale Branch Prediction (VMScape)**

After a guest VM exits to the host, stale branch predictions from the guest can influence host-side speculative execution before the kernel returns to userspace, allowing a local attacker to leak host kernel memory. This affects Intel processors from Sandy Bridge through Arrow Lake/Lunar Lake, AMD Zen 1 through Zen 5 families, and Hygon family 0x18. Only systems running a hypervisor with untrusted guests are at risk. Mitigation requires a kernel update (CONFIG_MITIGATION_VMSCAPE, Linux 6.18+) that issues IBPB before returning to userspace after a VM exit. No specific microcode update is required beyond existing IBPB support. Performance impact is low.

**CVE-2024-45332 — Branch Privilege Injection (BPI)**

A race condition in the branch predictor update mechanism of Intel processors (Coffee Lake through Raptor Lake, plus some server and Atom parts) allows user-space branch predictions to briefly influence kernel-space speculative execution, undermining eIBRS and IBPB protections. This means systems relying solely on eIBRS for Spectre V2 mitigation may not be fully protected without the microcode fix. Mitigation requires a microcode update (intel-microcode 20250512+) that fixes the asynchronous branch predictor update timing so that eIBRS and IBPB work as originally intended. No kernel changes are required. Performance impact is negligible.

</details>

## Unsupported CVEs

Several transient execution CVEs are not covered by this tool, for various reasons (duplicates, only
affecting non-supported hardware or OS, theoretical with no known exploitation, etc.).
The complete list along with the reason for each exclusion is available in the
[UNSUPPORTED_CVE_LIST.md](https://github.com/speed47/spectre-meltdown-checker/blob/source/UNSUPPORTED_CVE_LIST.md) file.

## Scope

Supported operating systems:
- Linux (all versions, flavors and distros)
- FreeBSD, NetBSD, DragonFlyBSD and derivatives (others BSDs are [not supported](FAQ.md#which-bsd-oses-are-supported))

For Linux systems, the tool will detect mitigations, including backported non-vanilla patches, regardless of the advertised kernel version number and the distribution (such as Debian, Ubuntu, CentOS, RHEL, Fedora, openSUSE, Arch, ...), it also works if you've compiled your own kernel. More information [here](FAQ.md#how-does-this-script-work).

Other operating systems such as MacOS, Windows, ESXi, etc. [will never be supported](FAQ.md#why-is-my-os-not-supported).

Supported architectures:
- `x86` (32 bits)
- `amd64`/`x86_64` (64 bits)
- `ARM` and `ARM64`
- other architectures will work, but mitigations (if they exist) might not always be detected

## Frequently Asked Questions (FAQ)

What is the purpose of this tool? Why was it written? How can it be useful to me? How does it work? What can I expect from it?

All these questions (and more) have detailed answers in the [FAQ](FAQ.md), please have a look!

## Running the script

### Direct way (recommended)

- Get the latest version of the script using `curl` *or* `wget`

```bash
curl -L https://meltdown.ovh -o spectre-meltdown-checker.sh
wget https://meltdown.ovh -O spectre-meltdown-checker.sh
```

- Inspect the script. You never blindly run scripts you downloaded from the Internet, do you?

```bash
vim spectre-meltdown-checker.sh
```

- When you're ready, run the script as root

```bash
chmod +x spectre-meltdown-checker.sh
sudo ./spectre-meltdown-checker.sh
```

### Using a docker container

<details>
<summary>Unfold for instructions</summary>

Using `docker compose`:

```shell
docker compose build
docker compose run --rm spectre-meltdown-checker
```

Note that on older versions of docker, `docker-compose` is a separate command, so you might
need to replace the two `docker compose` occurences above by `docker-compose`.

Using `docker build` directly:

```shell
docker build -t spectre-meltdown-checker .
docker run --rm --privileged -v /boot:/boot:ro -v /dev/cpu:/dev/cpu:ro -v /lib/modules:/lib/modules:ro spectre-meltdown-checker
```

</details>

## Example of script output

- Intel Haswell CPU running under Ubuntu 16.04 LTS

![haswell](https://user-images.githubusercontent.com/218502/108764885-6dcfc380-7553-11eb-81ac-4d19060a3acf.png)

- AMD Ryzen running under OpenSUSE Tumbleweed

![ryzen](https://user-images.githubusercontent.com/218502/108764896-70321d80-7553-11eb-9dd2-fad2a0a1a737.png)

- Batch mode (JSON flavor)

![batch](https://user-images.githubusercontent.com/218502/108764902-71634a80-7553-11eb-9678-fd304995fa64.png)

