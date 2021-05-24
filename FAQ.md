# Questions

- [Why was this script written in the first place?](#why-was-this-script-written-in-the-first-place)
- [Why are those vulnerabilities so different than regular CVEs?](#why-are-those-vulnerabilities-so-different-than-regular-cves)
- [What do "affected", "vulnerable" and "mitigated" mean exactly?](#what-do-affected-vulnerable-and-mitigated-mean-exactly)
- [What are the main design decisions regarding this script?](#what-are-the-main-design-decisions-regarding-this-script)
- [Everything is indicated in `sysfs` now, is this script still useful?](#everything-is-indicated-in-sysfs-now-is-this-script-still-useful)
- [How does this script work?](#how-does-this-script-work)
- [Which BSD OSes are supported?](#which-bsd-oses-are-supported)
- [Why is my OS not supported?](#why-is-my-os-not-supported)

# Answers

## Why was this script written in the first place?

The first commit of this script is dated *2018-01-07*, only 4 days after the world first heard about the Meltdown and the Spectre attacks. With those attacks disclosure, a _whole new range of vulnerabilities_ that were previously thought to be mostly theoretical and only possible in very controlled environments (labs) - hence of little interest for most except researchers - suddenly became completely mainstream and apparently trivial to conduct on an immensely large number of systems.

On the few hours and days after that date, the whole industry went crazy. Proper, verified information about these vulnerabilities was incredibly hard to find, because before this, even the CPU vendors never had to deal with managing security vulnerabilities at scale, as software vendors do since decades. There were a lot of FUD, and the apparent silence of the vendors was enough for most to fear the worst. The whole industry had everything to learn about this new type of vulnerabilities. However, most systems administrators had a few simple questions:

- Am **I** vulnerable? And if yes,
- What do I have to do to mitigate these vulnerabilities on **my** system?

Unfortunately, answering those questions was very difficult (and still is to some extent), even if the safe answer to the first question was "you probably are". This script was written to try to give simple answers to those simple questions, and was made to evolve as the information about these vulnerabilities became available. On the first few days, there was several new versions published **per day**.

## Why are those vulnerabilities so different than regular CVEs?

Those are hardware vulnerabilities, while most of the CVEs we see everyday are software vulnerabilities. A quick comparison would be:

Software vulnerability:
- Can be fixed? Yes.
- How to fix? Update the software (or uninstall it!)

Hardware vulnerability:
- Can be fixed? No, only mitigated (or buy new hardware!)
- How to ~~fix~~ mitigate? In the worst case scenario, 5 "layers" need to be updated: the microcode/firmware, the host OS kernel, the hypervisor, the VM OS kernel, and possibly all the software running on the VM.

A more detailed video explanation is available here: https://youtu.be/2gB9U1EcCss?t=85

## What do "affected", "vulnerable" and "mitigated" mean exactly?

- **Affected** means that your CPU's hardware, as it went out of the factory, is known to be concerned by a specific vulnerability, i.e. the vulnerability applies to your hardware model. Note that it says nothing about whether a given vulnerability can actually be used to exploit your system. However, an unaffected CPU will never be vulnerable, and doesn't need to have mitigations in place.
- **Vulnerable** implies that you're using an **affected** CPU, and means that a given vulnerability can be exploited on your system, because no (or insufficient) mitigations are in place.
- **Mitigated** implies that a previously **vulnerable** system has followed all the steps (updated all the required layers) to ensure a given vulnerability cannot be exploited. About what "layers" mean, see [the previous question](#why-are-those-vulnerabilities-so-different-than-regular-cves).

## What are the main design decisions regarding this script?

1) It should be okay to run this script in a production environment. This implies, but is not limited to:

   * 1a. Never modify the system it's running on, and if it needs to e.g. load a kernel module it requires, that wasn't loaded before it was launched, it'll take care to unload it on exit
   * 1b. Never attempt to "fix" or "mitigate" any vulnerability, or modify any configuration. It just reports what it thinks is the status of your system. It leaves all decisions to the sysadmin.
   * 1c. Never attempt to run any kind of exploit to tell whether a vulnerability is mitigated, because it would violate 1a), could lead to unpredictable system behavior, and might even lead to wrong conclusions, as some PoC must be compiled with specific options and prerequisites, otherwise giving wrong information (especially for Spectre). If you want to run PoCs, do it yourself, but please read carefully about the PoC and the vulnerability. PoCs about a hardware vulnerability are way more complicated and prone to false conclusions that PoCs for software vulnerabilities.

2) Never look at the kernel version to tell whether it supports mitigation for a given vulnerability. This implies never hardcoding version numbers in the script. This would defeat the purpose: this script should be able to detect mitigations in unknown kernels, with possibly backported or forward-ported patches. Also, don't believe what `sysfs` says, when possible. See the next question about this.

3) Never look at the microcode version to tell whether it has the proper mechanisms in place to support mitigation for a given vulnerability. This implies never hardcoding version numbers in the script. Instead, look for said mechanisms, as the kernel would do.

4) When a CPU is not known to be explicitly unaffected by a vulnerability, make the assumption that it is. This strong design choice has it roots in the early speculative execution vulnerability days (see [this answer](#why-was-this-script-written-in-the-first-place)), and is still a good approach as of today.

## Everything is indicated in `sysfs` now, is this script still useful?

A lot as changed since 2018. Nowadays, the industry adapted and this range of vulnerabilities is almost "business as usual", as software vulnerabilities are. However, due to their complexity, it's still not as easy as just checking a version number to ensure a vulnerability is closed.

Granted, we now have a standard way under Linux to check whether our system is affected, vulnerable, mitigated against most of these vulnerabilities. By having a look at the `sysfs` hierarchy, and more precisely the `/sys/devices/system/cpu/vulnerabilities/` folder, one can have a pretty good insight about its system state for each of the listed vulnerabilities. Note that the output can be a little different with some vendors (e.g. Red Hat has some slightly different output than the vanilla kernel for some vulnerabilities), but it's still a gigantic leap forward, given where we were in 2018 when this script was started, and it's very good news. The kernel is the proper place to have this because the kernel knows everything about itself (the mitigations it might have), and the CPU (its model, and microcode features that are exposed).

However I see a few reasons why this script might still be useful to you, and that's why its development has not halted when the `sysfs` hierarchy came out:

- A given version of the kernel doesn't have knowledge about the future. To put it in another way: a given version of the kernel only has the understanding of a vulnerability available at the time it was compiled. Let me explain this: when a new vulnerability comes out, new versions of the microcode and kernels are released, with mitigations in place. With such a kernel, a new `sysfs` entry will appear. However, after a few weeks or months, corner cases can be discovered, previously-thought unaffected CPUs can turn out to be affected in the end, and sometimes mitigations can end up being insufficient.  Of course, if you're always running the latest kernel version from kernel.org, this issue might be limited for you. The spectre-meltdown-checker script doesn't depend on a kernel's knowledge and understanding of a vulnerability to compute its output. That is, unless you tell it to (using the `--sysfs-only` option).

- Mitigating a vulnerability completely can sometimes be tricky, and have a lot of complicated prerequisites, depending on your kernel version, CPU vendor, model and even sometimes stepping, CPU microcode, hypervisor support, etc. The script gives a very detailed insight about each of the prerequisites of mitigation for every vulnerability, step by step, hence pointing out what is missing on your system as a whole to completely mitigate an issue.

- The script can be pointed at a kernel image, and will deep dive into it, telling you if this kernel will mitigate vulnerabilities that might be present on your system. This is a good way to verify before booting a new kernel, that it'll mitigate the vulnerabilities you expect it to, especially if you modified a few config options around these topics.

- The script will also work regardless of the custom patches that might be integrated in the kernel you're running (or you're pointing it to, in offline mode), and completely ignores the advertised kernel version, to tell whether a given kernel mitigates vulnerabilities. This is especially useful for non-vanilla kernel, where patches might be backported, sometimes silently (this has already happened, too).

- Educational purposes: the script gives interesting insights about a vulnerability, and how the different parts of the system work together to mitigate it.

There are probably other reasons, but that are the main ones that come to mind. In the end, of course, only you can tell whether it's useful for your use case ;)

## How does this script work?

On one hand, the script gathers information about your CPU, and the features exposed by its microcode. To do this, it uses the low-level CPUID instruction (through the `cpuid` kernel module under Linux, and the `cpucontrol` tool under BSD), and queries to the MSR registers of your CPU (through the `msr` kernel module under Linux, and the `cpucontrol` tool under BSD).

On another hand, the script looks into the kernel image your system is running on, for clues about the mitigations it supports. Of course, this is very specific for each operating system, even if the implemented mitigation is functionally the same, the actual code is completely specific. As you can imagine, the Linux kernel code has a few in common with a BSD kernel code, for example. Under Linux, the script supports looking into the kernel image, and possibly the System.map and kernel config file, if these are available. Under BSD, it looks into the kernel file only.

Then, for each vulnerability it knows about, the script decides whether your system is [affected, vulnerable, and mitigated](#what-do-affected-vulnerable-and-mitigated-mean-exactly) against it, using the information it gathered about your hardware and your kernel.

## Which BSD OSes are supported?

For the BSD range of operating systems, the script will work as long as the BSD you're using supports `cpuctl` and `linprocfs`. This is not the case for OpenBSD for example. Known BSD flavors having proper support are: FreeBSD, NetBSD, DragonflyBSD. Derivatives of those should also work. To know why other BSDs will likely never be supported, see [why is my OS not supported?](#why-is-my-os-not-supported).

## Why is my OS not supported?

This script only supports Linux, and [some flavors of BSD](#which-bsd-oses-are-supported). Other OSes will most likely never be supported, due to [how this script works](#how-does-this-script-work). It would require implementing these OSes specific way of querying the CPU. It would also require to get documentation (if available) about how this OS mitigates each vulnerability, down to this OS kernel code, and if documentation is not available, reverse-engineer the difference between a known old version of a kernel, and a kernel that mitigates a new vulnerability.
