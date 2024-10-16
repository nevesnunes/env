# +

- Try fixed wi-fi channel (e.g. 6)
- Debug logs: wireless driver + wpa_supplicant
	- ~/opt/restart_wpa.sh
	- [!] avoid more than one manager service running at the same time (e.g. wpa_supplicant and NetworkManager)

```bash
iw wlp3s0 info

dhclient -r
dhclient wlan0
nmcli dev
nmcli radio wifi on
```

I finally got wireless working. It took me 2 days to figure it out, but I think I finally understand Ubuntu networking a little bit better. Let me summarize it for you, so one day it may save someone else some time:

My quest: to connect to the internet through a wireless router, using PSA-PSK as wireless authentication protocol. The network card is a D-Link AirPlusG+ DWL-G520+ PCI card, which has a Texas Instruments ACX 111 chipset. There is also a wired network card with a Realtek chipset in the same system, but that is not very relevant here since I really want to get the wireless to work.

Where it went wrong: after installation, I wanted to switch to the wireless interface. I had tried enabling WPA-PSK via System->Administration->Network, but as soon as I did that the system froze. It kept on freezing upon reboot.

Linux is about choices. The problem is that it's not always clear what the choices are and which ones to make. So here is a guide:

- Choose the driver for your card. There is an open-source driver for the chipset: http://acx100.sourceforge.net/, but the current version does not support WPA-PSK. The alternative is to use the ndiswrapper http://ndiswrapper.sourceforge.net/joomla/index.php?/, which is a Linux wrapper around the Windows driver. It requires you to download and unzip the windows drivers, but it works with WPA-PSK.
- Choose how you want to manage the network. Network manager https://help.ubuntu.com/community/NetworkManager is the default in Ubuntu, unfortunately it is still beta and it does not work well with this hardware in combination with WPA-PSK (it freezes the system). Network interfaces under control of network manager will show up as "Roaming" under System->Administration->Network. So the alternative is to disable network manager and manually manage the /etc/network/interfaces. The downside is that the nifty network status icons in the top right bar are gone. Check out the link to see how it's done.
- Choose the wireless authentication protocol. WPA offers better security than WEP, so I'll go for WPA. For WPA-PSK in combination with the ndiswrapper driver, you need wpa_supplicant http://hostap.epitest.fi/wpa_supplicant/. This means manually editing /etc/wpa_supplicant.conf and /etc/network/interfaces.

```
peter@dolphin:~$ cat /etc/wpa_supplicant.conf 
ctrl_interface=/var/run/wpa_supplicant

network={
	ssid="myssid"
	scan_ssid=1
	proto=WPA
	key_mgmt=WPA-PSK
	pairwise=TKIP
	group=TKIP
	psk=thisisakeyinhex
}

peter@dolphin:~$ cat /etc/network/interfaces 
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp

auto wlan0
iface wlan0 inet dhcp
pre-up wpa_supplicant -Bw -Dndiswrapper -iwlan0 -c/etc/wpa_supplicant.conf
post-down killall -q wpa_supplicant
```
