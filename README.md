Spectre & Meltdown Checker
==========================

A simple shell script to tell if your Linux installation is vulnerable against the 3 "speculative execution" CVEs.

Without options, it'll inspect you currently running kernel. 
You can also specify a kernel image on the command line, if you'd like to inspect a kernel you're not running.

The script will do its best to detect mitigations, including backported non-vanilla patches, regardless of the advertised kernel version number.

## Example of script output

![checker](https://framapic.org/FjroIZximyoM/EO5msoSMKb6L.png)

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
