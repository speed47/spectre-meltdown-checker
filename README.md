Spectre & Meltdown Checker
==========================

A simple shell script to tell if your Linux installation is vulnerable against the 3 "speculative execution" CVEs that were made public early 2018.

Without options, it'll inspect your currently running kernel. 
You can also specify a kernel image on the command line, if you'd like to inspect a kernel you're not running.

The script will do its best to detect mitigations, including backported non-vanilla patches, regardless of the advertised kernel version number.

## Example of script output

- Intel Haswell CPU running under Ubuntu 16.04 LTS

![haswell](https://framapic.org/1kWmNwE6ll0p/ayTRX9JRlHJ7.png)

- AMD Ryzen running under OpenSUSE Tumbleweed

![ryzen](https://framapic.org/TkWbuh421YQR/6MAGUP3lL6Ne.png)

- Batch mode (JSON flavor)

![batch](https://framapic.org/HEcWFPrLewbs/om1LdufspWTJ.png)

## Quick Run Command

```bash
curl -L https://raw.githubusercontent.com/speed47/spectre-meltdown-checker/master/spectre-meltdown-checker.sh | sudo bash

# With JSON output
curl -L https://raw.githubusercontent.com/speed47/spectre-meltdown-checker/master/spectre-meltdown-checker.sh | sudo bash -s -- --batch json 2>/dev/null | jq .

```

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

## Disclaimer

This tool does its best to determine whether your system is immune (or has proper mitigations in place) for the collectively named "speculative execution" vulnerabilities. It doesn't attempt to run any kind of exploit, and can't guarantee that your system is secure, but rather helps you verifying whether your system has the known correct mitigations in place.
However, some mitigations could also exist in your kernel that this script doesn't know (yet) how to detect, or it might falsely detect mitigations that in the end don't work as expected (for example, on backported or modified kernels).

Your system exposure also depends on your CPU. As of now, AMD and ARM processors are marked as immune to some or all of these vulnerabilities (except some specific ARM models). All Intel processors manufactured since circa 1995 are thought to be vulnerable, except some specific/old models, such as some early Atoms. Whatever processor one uses, one might seek more information from the manufacturer of that processor and/or of the device in which it runs.

The nature of the discovered vulnerabilities being quite new, the landscape of vulnerable processors can be expected to change over time, which is why this script makes the assumption that all CPUs are vulnerable, except if the manufacturer explicitly stated otherwise in a verifiable public announcement.

Please also note that for Spectre vulnerabilities, all software can possibly be exploited, this tool only verifies that the kernel (which is the core of the system) you're using has the proper protections in place. Verifying all the other software is out of the scope of this tool. As a general measure, ensure you always have the most up to date stable versions of all the softwares you use, especially for those who are exposed to the world, such as network daemons and browsers.

This tool has been released in the hope that it'll be useful, but don't use it to jump to conclusions about your security.
