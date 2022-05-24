# Debugging

- `/dev/usbmon`: collect traces of I/O on the USB bus, analogous to a packet socket used by network monitoring tools such as `tcpdump`
- [GitHub \- djpnewton/busdog: busdog is a filter driver for MS Windows \(XP and above\) to sniff USB traffic\.](https://github.com/djpnewton/busdog)

- ~/Downloads/USB_Debugging_and_Profiling_Techniques.pdf

# Hub ports, 2.0 vs. 3.0

```bash
lsusb | sort
lspci | grep USB

# Match paths from /sys with /dev
find /sys/bus/usb/devices/usb*/ -name dev | while IFS= read -r sysdevpath; do
    syspath="${sysdevpath%/dev}"
    devname="$(udevadm info -q name -p "$syspath")"
    case "$devname" in
      'bus/'*)
        eval "$(udevadm info -q property --export -p "$syspath" | grep ID_SERIAL)"
        if [ -n "$ID_SERIAL" ]; then
            echo "$ID_SERIAL - /dev/$devname - $sysdevpath"
        fi
        unset ID_SERIAL
    esac
done | sort
```

Check hardware port: 

- extra conductors
- super speed (SS) label

https://askubuntu.com/questions/217676/how-do-i-find-out-whether-my-system-has-usb-3-0-ports

# Version

```bash
lsusb -v
```

Look at board, google `$ID datasheet`

### Windows

```
devcon hwids =usb
```

- https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-device-descriptors
- https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/devcon

# USB1 support

Use USB2 hub with Multi Transaction Translator (Multi-TT)
