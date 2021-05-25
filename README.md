Spectre & Meltdown Checker
==========================

A shell script to assess your system's resilience against the several [transient execution](https://en.wikipedia.org/wiki/Transient_execution_CPU_vulnerability) CVEs that were published since early 2018, and give you guidance as to how to mitigate them.

CVE                                                                             | Name                                                | Aliases
------------------------------------------------------------------------------- | --------------------------------------------------- | ---------------------------------
[CVE-2017-5753](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754)   | Bounds Check Bypass                                 | Spectre Variant 1
[CVE-2017-5715](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5715)   | Branch Target Injection                             | Spectre Variant 2
[CVE-2017-5754](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5754)   | Rogue Data Cache Load                               | Meltdown, Variant 3
[CVE-2018-3640](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3640)   | Rogue System Register Read                          | Variant 3a
[CVE-2018-3639](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3639)   | Speculative Store Bypass                            | Variant 4
[CVE-2018-3615](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3615)   | L1 Terminal Fault                                   | L1TF, Foreshadow (SGX)
[CVE-2018-3620](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3620)   | L1 Terminal Fault                                   | L1TF, Foreshadow-NG (OS)
[CVE-2018-3646](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-3646)   | L1 Terminal Fault                                   | L1TF, Foreshadow-NG (VMM)
[CVE-2018-12126](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12126) | Microarchitectural Store Buffer Data Sampling       | MSBDS, Fallout
[CVE-2018-12130](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12130) | Microarchitectural Fill Buffer Data Sampling        | MFBDS, ZombieLoad
[CVE-2018-12127](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12127) | Microarchitectural Load Port Data Sampling          | MLPDS, RIDL
[CVE-2019-11091](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11091) | Microarchitectural Data Sampling Uncacheable Memory | MDSUM, RIDL
[CVE-2019-11135](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11135) | TSX asynchronous abort                              | TAA, ZombieLoad V2
[CVE-2018-12207](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12207) | Machine Mheck Exception on Page Size Changes        | MCEPSC, No eXcuses, iTLB Multihit
[CVE-2020-0543](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0543)   | Special Register Buffer Data Sampling               | SRBDS

Supported operating systems:
- Linux (all versions, flavors and distros)
- FreeBSD, NetBSD, DragonFlyBSD and derivatives (others BSDs are [not supported](FAQ.md#which-bsd-oses-are-supported))

For Linux systems, the tool will detect mitigations, including backported non-vanilla patches, regardless of the advertised kernel version number and the distribution (such as Debian, Ubuntu, CentOS, RHEL, Fedora, openSUSE, Arch, ...), it also works if you've compiled your own kernel. More information [here](FAQ.md#how-does-this-script-work).

Other operating systems such as MacOS, Windows, ESXi, etc. [will most likely never be supported](FAQ.md#why-is-my-os-not-supported).

Supported architectures:
- `x86` (32 bits)
- `amd64`/`x86_64` (64 bits)
- `ARM` and `ARM64`
- other architectures will work, but mitigations (if they exist) might not always be detected

## Frequently Asked Questions (FAQ)

- What is the purpose of this tool?
- Why was it written?
- How can it be useful to me?
- How does it work?
- What can I expect from it?

All these questions (and more) have detailed answers in the [FAQ](FAQ.md), please have a look!

## Easy way to run the script

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

### Run the script in a docker container

#### With docker-compose

```shell
docker-compose build
docker-compose run --rm spectre-meltdown-checker
```

#### Without docker-compose

```shell
docker build -t spectre-meltdown-checker .
docker run --rm --privileged -v /boot:/boot:ro -v /dev/cpu:/dev/cpu:ro -v /lib/modules:/lib/modules:ro spectre-meltdown-checker
```

## Example of script output

- Intel Haswell CPU running under Ubuntu 16.04 LTS

![haswell](https://user-images.githubusercontent.com/218502/108764885-6dcfc380-7553-11eb-81ac-4d19060a3acf.png)

- AMD Ryzen running under OpenSUSE Tumbleweed

![ryzen](https://user-images.githubusercontent.com/218502/108764896-70321d80-7553-11eb-9dd2-fad2a0a1a737.png)

- Batch mode (JSON flavor)

![batch](https://user-images.githubusercontent.com/218502/108764902-71634a80-7553-11eb-9678-fd304995fa64.png)

## Quick summary of the CVEs

**CVE-2017-5753** bounds check bypass (Spectre Variant 1)

   - Impact: Kernel & all software
   - Mitigation: recompile software *and* kernel with a modified compiler that introduces the LFENCE opcode at the proper positions in the resulting code
   - Performance impact of the mitigation: negligible

**CVE-2017-5715** branch target injection (Spectre Variant 2)

   - Impact: Kernel
   - Mitigation 1: new opcode via microcode update that should be used by up to date compilers to protect the BTB (by flushing indirect branch predictors)
   - Mitigation 2: introducing "retpoline" into compilers, and recompile software/OS with it
   - Performance impact of the mitigation: high for mitigation 1, medium for mitigation 2, depending on your CPU

**CVE-2017-5754** rogue data cache load (Meltdown)

   - Impact: Kernel
   - Mitigation: updated kernel (with PTI/KPTI patches), updating the kernel is enough
   - Performance impact of the mitigation: low to medium

**CVE-2018-3640** rogue system register read (Variant 3a)

   - Impact: TBC
   - Mitigation: microcode update only
   - Performance impact of the mitigation: negligible

**CVE-2018-3639** speculative store bypass (Variant 4)

   - Impact: software using JIT (no known exploitation against kernel)
   - Mitigation: microcode update + kernel update making possible for affected software to protect itself
   - Performance impact of the mitigation: low to medium

**CVE-2018-3615** l1 terminal fault (Foreshadow-NG SGX)

   - Impact: Kernel & all software (any physical memory address in the system)
   - Mitigation: microcode update
   - Performance impact of the mitigation: negligible

**CVE-2018-3620** l1 terminal fault (Foreshadow-NG SMM)

   - Impact: Kernel & System management mode
   - Mitigation: updated kernel (with PTE inversion)
   - Performance impact of the mitigation: negligible

**CVE-2018-3646** l1 terminal fault (Foreshadow-NG VMM)

   - Impact: Virtualization software and Virtual Machine Monitors
   - Mitigation: disable ept (extended page tables), disable hyper-threading (SMT), or updated kernel (with L1d flush)
   - Performance impact of the mitigation: low to significant

**CVE-2018-12126** [MSBDS] Microarchitectural Store Buffer Data Sampling (Fallout)

**CVE-2018-12130** [MFBDS] Microarchitectural Fill Buffer Data Sampling (ZombieLoad)

**CVE-2018-12127** [MLPDS] Microarchitectural Load Port Data Sampling (RIDL)

**CVE-2019-11091** [MDSUM] Microarchitectural Data Sampling Uncacheable Memory (RIDL)

   - Note: These 4 CVEs are similar and collectively named "MDS" vulnerabilities, the mitigation is identical for all
   - Impact: Kernel
   - Mitigation: microcode update + kernel update making possible to protect various CPU internal buffers from unprivileged speculative access to data
   - Performance impact of the mitigation: low to significant

**CVE-2019-11135** TSX Asynchronous Abort (TAA, ZombieLoad V2)

   - Impact: Kernel
   - Mitigation: microcode update + kernel update making possible to protect various CPU internal buffers from unprivileged speculative access to data
   - Performance impact of the mitigation: low to significant

**CVE-2018-12207** machine check exception on page size changes (No eXcuses, iTLB Multihit)

   - Impact: Virtualization software and Virtual Machine Monitors
   - Mitigation: disable hugepages use in hypervisor, or update hypervisor to benefit from mitigation
   - Performance impact of the mitigation: low to significant

**CVE-2020-0543** Special Register Buffer Data Sampling (SRBDS)

   - Impact: Kernel
   - Mitigation: microcode update + kernel update helping to protect various CPU internal buffers from unprivileged speculative access to data
   - Performance impact of the mitigation: low
