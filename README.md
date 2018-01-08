Spectre & Meltdown Checker
==========================

A simple shell script to tell if your Linux installation is vulnerable against the 3 "speculative execution" CVEs.

Without options, it'll inspect you currently running kernel. 
You can also specify a kernel image on the command line, if you'd like to inspect a kernel you're not running.

The script will do its best to detect mitigations, including backported non-vanilla patches, regardless of the advertised kernel version number.

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

## Example of script output

### Ubuntu LTS (before official patches)

```
$ sudo ./spectre-and-meltdown.sh
Spectre and Meltdown mitigation detection tool v0.16

Checking for vulnerabilities against live running kernel Linux 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64
Will use vmlinux image /boot/vmlinuz-4.4.0-104-generic
Will use kconfig /boot/config-4.4.0-104-generic
Will use System.map file /boot/System.map-4.4.0-104-generic

CVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'
* Kernel compiled with LFENCE opcode inserted at the proper places:  NO  (only 38 opcodes found, should be >= 70)
> STATUS:  VULNERABLE 

CVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'
* Mitigation 1
*   Hardware (CPU microcode) support for mitigation:  NO 
*   Kernel support for IBRS:  NO 
*   IBRS enabled for Kernel space:  NO 
*   IBRS enabled for User space:  NO 
* Mitigation 2
*   Kernel compiled with retpoline option:  NO 
*   Kernel compiled with a retpoline-aware compiler:  NO 
> STATUS:  VULNERABLE  (IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability)

CVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'
* Kernel supports Page Table Isolation (PTI):  NO 
* PTI enabled and active:  NO 
> STATUS:  VULNERABLE  (PTI is needed to mitigate the vulnerability)
```

### First patched kernel of RHEL6

```
$ sudo ./spectre-meltdown-checker.sh --kernel /tmp/vmlinuz-2.6.32-696.18.7.el6.x86_64 --config /tmp/config-2.6.32-696.18.7.el6.x86_64 --map /tmp/System.map-2.6.32-696.18.7.el6.x86_64
Spectre and Meltdown mitigation detection tool v0.16

Checking for vulnerabilities against specified kernel
Will use vmlinux image /tmp/vmlinuz-2.6.32-696.18.7.el6.x86_64
Will use kconfig /tmp/config-2.6.32-696.18.7.el6.x86_64
Will use System.map file /tmp/System.map-2.6.32-696.18.7.el6.x86_64

CVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'
* Kernel compiled with LFENCE opcode inserted at the proper places:  YES  (84 opcodes found, which is >= 70)
> STATUS:  NOT VULNERABLE 

CVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'
* Mitigation 1
*   Hardware (CPU microcode) support for mitigation:  NO 
*   Kernel support for IBRS:  YES 
*   IBRS enabled for Kernel space:  N/A  (not testable in offline mode)
*   IBRS enabled for User space:  N/A  (not testable in offline mode)
* Mitigation 2
*   Kernel compiled with retpoline option:  NO 
*   Kernel compiled with a retpoline-aware compiler:  NO 
> STATUS:  NOT VULNERABLE  (offline mode: IBRS will mitigate the vulnerability if enabled at runtime)

CVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'
* Kernel supports Page Table Isolation (PTI):  YES 
* PTI enabled and active:  N/A  (can't verify if PTI is enabled in offline mode)
> STATUS:  NOT VULNERABLE  (offline mode: PTI will mitigate the vulnerability if enabled at runtime)
```
