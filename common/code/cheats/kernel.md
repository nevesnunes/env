# +

- [code search](https://livegrep.com/search/linux)
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

https://wiki.archlinux.org/index.php/zswap

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

coredumpctl gdb "$(coredumpctl list | \
    tail -n1 | \
    grep -o '  [0-9]*  ' | \
    head -n1  | \
    grep -o '[0-9]*')"
```

# kill

http://www.noah.org/wiki/Kill_-9_does_not_work

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

https://lwn.net/Articles/486306/

# exec

https://wiki.archlinux.org/index.php/Binfmt_misc_for_Java
https://stackoverflow.com/questions/3009192/how-does-the-shebang-work
https://stackoverflow.com/questions/1667830/running-a-jar-file-without-directly-calling-java
https://www.kernel.org/doc/html/v4.12/admin-guide/binfmt-misc.html
https://www.kernel.org/doc/html/v4.12/admin-guide/java.html
https://www.in-ulm.de/~mascheck/various/shebang/
https://lwn.net/Articles/630727/

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
```

- https://www.kernel.org/doc/html/latest/firmware-guide/acpi/namespace.html
- https://01.org/linux-acpi/documentation/debug-how-isolate-linux-acpi-issues
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
        - on target (boot parameters): `kgdboc=ttymxc0,115200 kgdbwait`
        - on target (runtime):
            ```bash
            echo ttymxc0 > /sys/module/kgdboc/parameters/kgdboc
            echo g > /proc/sysrq-trigger
            ```
        - on host:
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
        - https://www.kernel.org/doc/html/latest/dev-tools/gdb-kernel-debugging.html
        - https://github.com/alesax/gdb-kdump
        - https://github.com/ptesarik/libkdumpfile
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
