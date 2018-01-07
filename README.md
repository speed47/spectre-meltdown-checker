Spectre & Meltdown Checker
==========================

A simple shell script to tell if your Linux installation is vulnerable
against the 3 "speculative execution" CVEs:

CVE-2017-5753 bounds check bypass (Spectre Variant 1)

   - Impact: Kernel & all software
   - Mitigation: recompile software *and* kernel with a modified compiler that introduces the LFENCE opcode at the proper positions in the resulting code
   - Performance impact of the mitigation: negligible

CVE-2017-5715: branch target injection (Spectre Variant 2)

   - Impact: Kernel
   - Mitigation 1: new opcode via microcode update that should be used by up to date compilers to protect the BTB (by flushing indirect branch predictors)
   - Mitigation 2: introducing "retpoline" into compilers, and recompile software/OS with it
   - Performance impact of the mitigation: high for mitigation 1, medium for mitigation 2, depending on your CPU

CVE-2017-5754: rogue data cache load (Meltdown)

   - Impact: Kernel
   - Mitigation: updated kernel (with PTI/KPTI patches), updating the kernel is enough
   - Performance impact of the mitigation: low to medium

Example of the output of the script:


```
$ sudo ./spectre-meltdown-checker.sh
Spectre and Meltdown mitigation detection tool v0.02

CVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'
* Kernel compiled with LFENCE opcode inserted at the proper places: NO (only 38 opcodes found, should be >= 60)
> STATUS: VULNERABLE

CVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'
* Mitigation 1
*   Hardware (CPU microcode) support for mitigation: NO
*   Kernel support for IBRS: NO
*   IBRS enabled for Kernel space: NO
*   IBRS enabled for User space: NO
* Mitigation 2
*   Kernel recompiled with retpolines: UNKNOWN (check not yet implemented)
> STATUS: VULNERABLE (IBRS hardware + kernel support OR retpolines-compiled kernel are needed to mitigate the vulnerability)

CVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'
* Kernel supports Page Table Isolation (PTI): YES
* PTI enabled and active: YES
> STATUS: NOT VULNERABLE (PTI mitigates the vulnerability)
```
