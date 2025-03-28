# +

- [code search](https://livegrep.com/search/linux)
- [kernelconfig\.io \- search config information for linux kernel modules](https://www.kernelconfig.io/index.html)
- [Linux Device Drivers, 3rd Edition](http://www.makelinux.net/ldd3/)

# headers

- For custom kernel, Location: `$custom_kernel_root/include`
    - Symlink: `/lib/modules/$kernel_version/build`

# configs

- /lib/modules
- /proc/config.gz
- https://github.com/systemd/systemd/blob/master/README
- https://www.freedesktop.org/software/systemd/man/journald.conf.html

# options

```
selinux=1 enforcing=0
nomodeset
systemd.unit=rescue.target
```

# modules

### info

```bash
# attributes / parameters
modinfo *
grep -H '' /sys/module/iwl*/parameters/*

# only loaded
lsmod
# ||
awk '/live/{split(FILENAME, a, "/"); print a[4]}' /sys/module/*/initstate
```

### list associated with usb device

```bash
dmesg
lsusb -t
usb-devices
# ||
needle=
for i in /sys/bus/usb/devices/*; do
	if grep -i "$needle" "$i"/{manufacturer,product} 2>/dev/null; then
		readlink "$i"/driver
		for j in "$i"/**/modalias; do
			<"$j" xargs -I{} modinfo {} 2>/dev/null | grep 'name\|depends'
		done
	fi
done
```

- https://unix.stackexchange.com/questions/60078/find-out-which-modules-are-associated-with-a-usb-device

### find config options for building given modules

```bash
module_name=
# `-B 3`: Account for guarded "ifeq" clauses
find . -iname 'Makefile*' -exec grep -Hin -B 3 "$module_name" {} \;
# Take "obj-$(CONFIG_FOO) += foo.o"
# Also check in outer Makefiles which "obj-" include inner Makefiles
```

- https://www.linuxtopia.org/online_books/linux_kernel/kernel_configuration/ch08s02.html
- https://stackoverflow.com/questions/45905642/mapping-kernel-config-variables-to-modules

### macro expansions

```bash
# Preprocessed source
make kernel/foo.i 
# Assembly output
make kernel/foo.s
```

### graphical (modeset)

```bash
grep DRI2 /var/log/Xorg.*.log
# || non-root instance
grep DRI2 ~/.local/share/xorg/Xorg.*.log
```

On `nouveau` loaded:

```
(II) modeset(G0): [DRI2]   DRI driver: nouveau
(II) modeset(G0): [DRI2]   VDPAU driver: nouveau
[...]
(II) modeset(0): [DRI2]   DRI driver: i965
(II) modeset(0): [DRI2]   VDPAU driver: va_gl
```

On `nouveau.modeset=0`: Only `i965` entry

### install

```bash
modprobe -r foo; modprobe foo
# ||
depmod -a # take dependencies of `foo`
insmod foo_dependency
insmod foo
```

- [How Do Modules Get Into The Kernel? \- The Linux Kernel Module Programming Guide](https://tldp.org/LDP/lkmpg/2.6/html/x44.html)
- https://wiki.ubuntu.com/KernelCustomBuild

# verify authenticity

```bash
xz -dc < linux-4.4.135.tar.xz > linux-4.4.135.tar
gpg --verify linux-4.4.135.tar.sign
```

# binds

- https://unix.stackexchange.com/questions/198590/what-is-a-bind-mount

### override read only file system (e.g. squashfs)

```bash
sudo mount --bind --bind -o nodev,ro /etc/ssl/certs /snap/core/current/etc/ssl/certs/
# ||
cat <<-EOF | sudo tee /etc/systemd/system/snap-core-current-etc-ssl-certs.mount
[Unit]
Description=Mount unit to fix etc ssl certs in core package
After=snapd.service

[Mount]
What=/etc/ssl/certs
Where=/snap/core/current/etc/ssl/certs
Type=none
Options=bind,nodev,ro

[Install]
WantedBy=multi-user.target
EOF
systemctl enable snap-core-current-etc-ssl-certs.mount
```

- https://forum.snapcraft.io/t/certificate-substitution-and-snaps/1077/6

# profiling

- Ftrace 2.6.27
- perf_events 2.6.31, 3.2
   - https://github.com/brendangregg/perf-tools
- eBPF 3.15, 4.1
   - https://github.com/iovisor/bcc

- https://www.kernel.org/doc/html/latest/trace/tracepoint-analysis.html#lower-level-analysis-with-pcl

# swap

- https://wiki.archlinux.org/index.php/zswap

# miscellaneous binary format interpreters

```bash
mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc
echo ':PDF:M::%PDF::/usr/bin/evince:' > /proc/sys/fs/binfmt_misc/register
```
https://www.kernel.org/doc/html/v4.11/admin-guide/binfmt-misc.html
https://ownyourbits.com/2018/06/13/transparently-running-binaries-from-any-architecture-in-linux-with-qemu-and-binfmt_misc/

# code dumps

```bash
sudo dnf dnf debuginfo-install libmutter\*

ulimit -c unlimited
entry='* soft core unlimited' && \
    sed -n -e "/^$entry/!p" -e '$a'"$entry" /etc/security/limits.conf
ulimit -a | grep -- -c
grep DumpLocation /etc/abrt/abrt.conf

key='kernel.core_pattern' && \
    sed -n -e "/^$key=/!p" -e '$a'"$key"' = /var/crash/core-%e-%s-%u-%g-%p-%t' /etc/sysctl.conf
key='DAEMON_COREFILE_LIMIT' && \
    sed -n -e "/^$key=/!p" -e '$a'"$key"' = unlimited' /etc/sysconfig/init
cat /proc/sys/kernel/core_pattern

semanage fcontext -a -t public_content_rw_t "/var/crash(/.*)?"
setsebool -P abrt_anon_write 1
service abrtd.service restart

coredumpctl gdb "$(coredumpctl list --json=short | jq '.[-1].pid')"
# ||
coredumpctl gdb "$(coredumpctl list | \
    tail -n1 | \
    grep -o '  [0-9]*  ' | \
    head -n1  | \
    grep -o '[0-9]*')"
```

- if only backtrace, then lookup address in disassembly
    - [How to debug kernel crashes](https://www.benzedrine.ch/crashreport.html)

# kill

- http://www.noah.org/wiki/Kill_-9_does_not_work

### oom killer

- decreasing reaping probability
    - `vm.overcommit_memory=2`
    - `oom_score_adj=-1000`
- cgroups
    - `/sys/fs/cgroup/memory/memory.usage_in_bytes`
    - `/sys/fs/cgroup/memory/memory.limit_in_bytes`
- https://www.crunchydata.com/blog/deep-postgresql-thoughts-the-linux-assassin

# suspend

- man
    - https://www.kernel.org/doc/Documentation/power/basic-pm-debugging.txt
    - https://wiki.ubuntu.com/DebuggingKernelHibernate
    - https://01.org/blogs/rzhang/2015/best-practice-debug-linux-suspend/hibernate-issues
- run
    - pm_trace
    - pm_test
    - https://unix.stackexchange.com/questions/62157/pm-utils-no-network-in-suspend-scripts/63498#63498
- usb
    ```bash
    usbcore.autosuspend=-1
    cat /sys/module/usbcore/parameters/autosuspend
    cat /sys/bus/usb/devices/1-2/power/autosuspend_delay_ms

    modprobe -r uhci_hcd
    modprobe uhci_hcd
    modprobe -r ehci_hcd
    modprobe ehci_hcd
    ```

# clear cache

```bash
sudo sh -c 'free && sync && echo 3 > /proc/sys/vm/drop_caches && free'
```

# capabilities

- [CAP\_SYS\_ADMIN: the new root \(LWN\.net\)](https://lwn.net/Articles/486306/)

# exec

- https://wiki.archlinux.org/index.php/Binfmt_misc_for_Java
- https://stackoverflow.com/questions/3009192/how-does-the-shebang-work
- https://stackoverflow.com/questions/1667830/running-a-jar-file-without-directly-calling-java
- https://www.kernel.org/doc/html/v4.12/admin-guide/binfmt-misc.html
- https://www.kernel.org/doc/html/v4.12/admin-guide/java.html
- https://www.in-ulm.de/~mascheck/various/shebang/
- https://lwn.net/Articles/630727/

# grub

```bash
vim /etc/default/grub
grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg
```

### view boot log

- On GRUB, edit (`e`) boot entry
   - Remove `quiet splash`, press `Alt-x`

### access boot menu

- Press `Esc`
    - If shell is open: type `normal`, press `Enter` + `Esc`

### parameters

- https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
- https://www.kernel.org/doc/Documentation/x86/x86_64/boot-options.txt

# hooking

- ~/Downloads/SystemCallHooking.c
- [An example of Hooking Linux System Call · GitHub](https://gist.github.com/mike820324/ba7b8c934f858fadc28b)

# boot without graphical features

- On GRUB: Select entry > Press `e` > `s/\(quiet splash\)/\1 nomodeset/` > Press `C-x`
- Alternative: nouveau.modeset=0 nvidia-drm.modeset=1

- https://www.dell.com/support/article/en-us/sln306327/manual-nomodeset-kernel-boot-line-option-for-linux-booting?lang=en

# boot without disk activity (forensics mode)

```bash
gsettings set org.gnome.desktop.media-handling automount false
```

### Debian (sysvinit)

- Parameter: `noswap`
	- On Debian, "/etc/init.d/checkroot.fs" checks for "$NOSWAP" after sourcing "/lib/init/vars.sh", which sets "$NOSWAP".

- [Disabling swap at boot](https://lists.ubuntu.com/archives/ubuntu-users/2011-February/240229.html)

### Debian (systemd)

- Parameter: `systemd.swap=`

- [Implement noswap kernel command line option \(for systemd\-fstab\-generator\) · Issue \#6686 · systemd/systemd · GitHub](https://github.com/systemd/systemd/issues/6686)

### Kali

- On GRUB: Select entry > Press `e` > `s/\(quiet splash\)/\1 noswap noautomount/` > Press `C-x`

- [noautomount/setup\-noautomount · debian/2019\.3\.6 · Kali Linux / Packages / kali\-defaults · GitLab](https://gitlab.com/kalilinux/packages/kali-defaults/-/blob/debian/2019.3.6/noautomount/setup-noautomount)

# syscall hooking

- ~/code/src/systems/linux-kernel-hook/
- https://medium.com/bugbountywriteup/linux-kernel-module-rootkit-syscall-table-hijacking-8f1bc0bd099c
- older kernels
	- https://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example
	- https://uwnthesis.wordpress.com/2016/12/26/basics-of-making-a-rootkit-from-syscall-to-hook/

# custom syscalls

- https://codingkaiser.blog/2021/07/17/create-your-own-system-calls%e2%80%8a-%e2%80%8aprocess-weights/

# namespaces

```bash
unshare --fork --pid --kill-child
```

# memory

- https://stackoverflow.com/questions/5463800/linux-memory-reporting-discrepancy?stw=2

# monitor filesystem events

```bash
auditctl -w /etc/foo -k id_foo -p rwxa
ausearch -f /etc/foo -i
```

- https://github.com/iovisor/bcc/blob/master/tools/statsnoop.py
- https://sourceware.org/systemtap/SystemTap_Beginners_Guide/inodewatchsect.html

# extract initramfs

```bash
cpio -idmv < initramfs.release.img
```

# acpi

```bash
grep '' /proc/acpi/wakeup | sort

# toggle enabled/disabled
echo EHC1 > /proc/acpi/wakeup
echo EHC2 > /proc/acpi/wakeup
echo XHCI > /proc/acpi/wakeup

# detect
acpi_listen
find /sys -iname wakeup_count -exec grep -H . {} \; | grep -v wakeup_count:0
find /sys -iname wakeup -type f -exec grep -H . {} \; | grep -v disabled
journalctl --since '30 minutes ago' | grep suspend

# /etc/systemd/logind.conf
# InhibitorsMax=0

# udev
find /sys -xdev -name '0000:00:14.0' -type d
udevadm info /sys/devices/pci0000:00/0000:00:14.0
# /etc/udev/rules.d/99-wakeup.rules
# ACTION=="add", SUBSYSTEM=="pci", DRIVERS=="xhci_hcd", ATTR{power/wakeup}="disabled"

# > if /proc/acpi/fan is empty and /proc/acpi/thermal_zone/*/trip_points has no active trip points (those starting with "AC") then there is no ACPI-based fan control on your system.
# > include/acpi/acoutput.h shows which flags can be enabled for level and layer, and cat /sys/module/acpi/parameters/debug_{level,layer} also shows you the flags.
echo 0x1F >/sys/module/acpi/parameters/debug_{level,layer}
```

Case study: NFS mounts cause suspend to fail

- No `wakeup_count` incrementing for devices
- https://bugs.launchpad.net/ubuntu/+source/linux/+bug/2076576

```sh
echo 1 > /sys/power/pm_trace
# [suspend]
dmesg -T
# [ 92.242978] Freezing of tasks failed after 20.008 seconds (1 tasks refusing to freeze, wq_busy=0):
# [ 92.243079] task:NFSv4 callback state:I stack: 0 pid: 1696 ppid: 2 flags:0x00004000
```

References:

- https://unix.stackexchange.com/questions/417956/make-changes-to-proc-acpi-wakeup-permanent
- https://www.kernel.org/doc/html/latest/firmware-guide/acpi/namespace.html
- https://wiki.ubuntu.com/DebuggingACPI
- https://wiki.ubuntu.com/Kernel/Reference/ACPITricksAndTips
- http://alexhungdmz.blogspot.com/2018/05/acpi-debugging-1-acpi-aml-debugger-in.html
- https://web.archive.org/web/20200924061451/https://01.org/linux-acpi/documentation/debug-how-isolate-linux-acpi-issues
    - https://bugzilla.kernel.org/show_bug.cgi?id=204251

# interrupts

```bash
grep '' /proc/interrupts
grep '' /sys/kernel/irq/*/*
```

- e.g. [diff before/after suspend](./reports/interrupts.md)
- [Add support to monitor interrupts through /sys/kernel/irq · Issue \#1416 · netdata/netdata · GitHub](https://github.com/netdata/netdata/issues/1416)

### irq handler

```c
#include <system.h>

void timer_handler(struct regs *r) {
    // ...
}

int main() {
    // IRQ0 = system clock
    irq_install_handler(0, timer_handler);

    return 0;
}
```

# debug

```bash
qemu-system-x86_64 -boot c -m 2048M -kernel linux-5.8/arch/x86/boot/bzImage -hda buildroot/output/images/rootfs.ext4 -nographic -append "root=/dev/sda rw console=ttyS0"

cd /usr/src/kernels/$kernel/
gdb /boot/vmlinux /proc/kcore
```

- interactive debugging
    - gdb server implementation: kgdb
        - on target:
            - .config:
                ```
                CONFIG_FRAME_POINTER=y
                CONFIG_GDB_SCRIPTS=y
                CONFIG_KGDB=y
                CONFIG_KGDB_SERIAL_CONSOLE=y
                CONFIG_STRICT_KERNEL_RWX=n
                ```
            - boot parameters: `kgdboc=ttyS0,115200 kgdbwait nokaslr`
            - || runtime config:
                ```bash
                echo ttyS0,115200 > /sys/module/kgdboc/parameters/kgdboc
                echo g > /proc/sysrq-trigger
                ```
        - on host:
            - VirtualBox: VM Settings > Serial Ports
                - Port Mode = Host Pipe
                - Path = /tmp/vboxS0
            - gdb client:
                ```sh
                gdb -ex 'set serial baud 115200' -ex 'target remote /tmp/vboxS0' -x /usr/src/linux-source-5.10/vmlinux-gdb.py /usr/src/linux-source-5.10/vmlinux
                ```
            - gdb session:
                ```gdb
                add-auto-load-safe-path /usr/src/kernels/$kernel/
                set serial baud 115200
                target remote /dev/ttyUSB0
                ```
        - if using serial port for both console and kgdb:
            ```bash
            git clone https://kernel.googlesource.com/pub/scm/utils/kernel/kgdb/agent-proxy
            cd agent-proxy/
            make
            ./agent-proxy 5550^5551 0 /dev/ttyUSB0,115200
            # on terminal 1
            telnet localhost 5550
            # on terminal 2
            gdb vmlinux
            # target remote localhost:5551
            ```
        - [Setup kgdboc for kernel debugging \– Aditya Basu](https://www.adityabasu.me/blog/2020/03/kgdboc-setup/)
        - [Using Serial kdb / kgdb to Debug the Linux Kernel \- eLinux](https://elinux.org/images/1/1b/ELC19_Serial_kdb_kgdb.pdf)
        - [Debugging kernel and modules via gdb \- The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/dev-tools/gdb-kernel-debugging.html)
        - [GitHub \- alesax/gdb\-kdump](https://github.com/alesax/gdb-kdump)
        - [GitHub \- ptesarik/libkdumpfile: Kernel coredump file access](https://github.com/ptesarik/libkdumpfile)
    - qemu running kernel
        ```bash
        qemu-system-arm -M vexpress-a9 -cpu cortex-a9 -m 256M -nographic -kernel ./zImage -append 'console=ttyAMA0,115200 rw nfsroot=10.0.2.2:/opt/debian/wheezy-armel-rootfs,v3 ip=dhcp' -dtb ./vexpress-v2p-ca9.dtb -s
        arm-linux-gnueabi-gdb vmlinux
        # target remote :1234
        ```
    - board bring-up: gdbremote compliant JTAG probe e.g. OpenOCD
- tracing
    - pin tools
    - systemtap
        - e.g. https://myaut.github.io/dtrace-stap-book/kernel/irq.html
    - https://www.kernel.org/doc/html/latest/trace/
- communication
    - /proc files
    - ioctl() syscalls
- hangs / lockups
    - CONFIG_HARDLOCKUP_DETECTOR, CONFIG_SOFTLOCKUP_DETECTOR
        - take $PC address from oops
    - ftrace
        ```bash
        trace-cmd record -p function_graph -O nofuncgraph-irqs -F foo > /proc/bar
        trace-cmd restore trace.dat.cpu0 trace.dat.cpu1 ...
        kernelshark trace.dat
        ```
    - magic sysrq
- memory leaks
    - /sys/kernel/debug/kmemleak
- oops
    - convert address to source line: `addr2line -f -e vmlinux 0x12345678`
    - store log: pstore
    - boot into dump: kdump, kexec
    - https://www.kernel.org/doc/html/latest/admin-guide/bug-hunting.html
- [GitHub \- bannsec/linux\-kernel\-lab: Lab Environment For Learning About The Linux Kernel](https://github.com/bannsec/linux-kernel-lab)

### References

- https://www.oreilly.com/library/view/linux-device-drivers/0596005903/ch04.html
- https://www.linux.it/~rubini/docs/kconf/
- https://www.kernel.org/doc/html/latest/kernel-hacking/hacking.html
- https://fedoraproject.org/wiki/How_to_debug_Dracut_problems
- https://e-labworks.com/talks/ew2020
- GDB and Linux Kernel Awareness - Peter Griffin

# testing

- [GitHub \- linux\-test\-project/ltp: Linux Test Project http://linux\-test\-project\.github\.io/](https://github.com/linux-test-project/ltp)

# hardening

- [GitHub \- a13xp0p0v/kconfig\-hardened\-check: A tool for checking the security hardening options of the Linux kernel](https://github.com/a13xp0p0v/kconfig-hardened-check)
- https://www.kicksecure.com/wiki/Hardened-kernel
- https://docs.windriver.com/bundle/Wind_River_Linux_Carrier_Grade_Profile_Users_Guide_9_1/page/rnb1487717713115.html
