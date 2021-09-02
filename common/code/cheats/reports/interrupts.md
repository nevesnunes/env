```bash
diff -uw /proc/interrupts <(sleep 2; cat /proc/interrupts)
```

```diff
--- /proc/interrupts    2020-01-11 10:26:31.865322061 +0000
+++ /proc/self/fd/11    2020-01-11 10:26:32.445329323 +0000
@@ -5,18 +5,18 @@
   9:         15          6          0          0   IO-APIC   9-fasteoi   acpi
  12:        126        143          0          0   IO-APIC  12-edge      i8042
  18:          0          0          0          0   IO-APIC  18-fasteoi   i801_smbus
- 23:     168477          0          0    1499582   IO-APIC  23-fasteoi   ehci_hcd:usb1
- 44:     648054          0     379269          0   PCI-MSI 512000-edge      ahci[0000:00:1f.2]
+ 23:     168478          0          0    1499582   IO-APIC  23-fasteoi   ehci_hcd:usb1
+ 44:     648061          0     379269          0   PCI-MSI 512000-edge      ahci[0000:00:1f.2]
  45:      17564          0          0          0   PCI-MSI 327680-edge      xhci_hcd
  46:          0          0          0          0   PCI-MSI 1048576-edge      enp2s0
  47:        183          0          0          0   PCI-MSI 2097152-edge      nvkm
- 48:     666016     265856          0          0   PCI-MSI 32768-edge      i915
+ 48:     666043     265856          0          0   PCI-MSI 32768-edge      i915
  49:          0         20          0          0   PCI-MSI 360448-edge      mei_me
  50:    1594285          0          0          0   PCI-MSI 1572864-edge      iwlwifi
  51:          0          0        150          0   PCI-MSI 442368-edge      snd_hda_intel:card1
  52:          0          0          0          0   PCI-MSI 49152-edge      snd_hda_intel:card0
 NMI:        150        734        683        650   Non-maskable interrupts
-LOC:   27402002   27569029   24095438   25895000   Local timer interrupts
+LOC:   27402001   27569028   24095438   25895000   Local timer interrupts
 SPU:          0          0          0          0   Spurious interrupts
 PMI:        150        734        683        650   Performance monitoring interrupts
 IWI:     204217      65510        451        304   IRQ work interrupts
```

```bash
diff -uw /proc/interrupts <(systemctl suspend; sleep 2; cat /proc/interrupts)
```

```diff
--- /proc/interrupts    2020-01-11 10:26:31.865322061 +0000
+++ /proc/self/fd/11    2020-01-11 10:27:37.356142043 +0000
@@ -1,16 +1,15 @@
            CPU0       CPU1       CPU2       CPU3
   0:          9          0          0          0   IO-APIC   2-edge      timer
-  1:         45          0         26          0   IO-APIC   1-edge      i8042
+  1:         59          0         26          0   IO-APIC   1-edge      i8042
   8:          0          0          0          1   IO-APIC   8-edge      rtc0
-  9:         15          6          0          0   IO-APIC   9-fasteoi   acpi
- 12:        126        143          0          0   IO-APIC  12-edge      i8042
+  9:         18          6          0          0   IO-APIC   9-fasteoi   acpi
+ 12:        169        143          0          0   IO-APIC  12-edge      i8042
  18:          0          0          0          0   IO-APIC  18-fasteoi   i801_smbus
- 23:     168645          0          0    1499582   IO-APIC  23-fasteoi   ehci_hcd:usb1
- 44:     648151          0     379269          0   PCI-MSI 512000-edge      ahci[0000:00:1f.2]
- 45:      17564          0          0          0   PCI-MSI 327680-edge      xhci_hcd
- 46:          0          0          0          0   PCI-MSI 1048576-edge      enp2s0
- 47:        183          0          0          0   PCI-MSI 2097152-edge      nvkm
- 48:     666646     265856          0          0   PCI-MSI 32768-edge      i915
+ 23:     168928          0          0    1499582   IO-APIC  23-fasteoi   ehci_hcd:usb1
+ 44:     648537          0     379269          0   PCI-MSI 512000-edge      ahci[0000:00:1f.2]
+ 45:      17565          0          0          0   PCI-MSI 327680-edge      xhci_hcd
+ 47:        197          0          0          0   PCI-MSI 2097152-edge      nvkm
+ 48:     666833     265856          0          0   PCI-MSI 32768-edge      i915
  49:          0         21          0          0   PCI-MSI 360448-edge      mei_me
  50:    1594953          0          0          0   PCI-MSI 1572864-edge      iwlwifi
  51:          0          0        188          0   PCI-MSI 442368-edge      snd_hda_intel:card1
```
