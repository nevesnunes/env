# APIs

https://github.com/phracker/MacOSX-SDKs

# shortcuts

- [!] Note: On vms, `Command` key = `Super` key
- Spotlight = `Cmd + Space`
- Xcode
    - Undo = `Cmd + z`
    - Navigation = `Cmd + Ctrl + Left/Right`
    - Find in project = `Cmd + Shift + f`
    - Find selected = `Cmd + e`

# directories

- Finder
    - Open (from shell) - `open .`
    - Goto folder - `Command + Shift + G`
- Unhide
    ```bash
    sudo chflags -R nohidden /*
    defaults write com.apple.finder AppleShowAllFiles TRUE
    ```
- Hierarchy
    - `/Volumes/` - Contains vm shared folders

# supported versions

- project.pbxproj || .xcconfig
    - isa = XCBuildConfiguration
    - buildSettings > TARGETED_DEVICE_FAMILY
        - maps to: UIDeviceFamily - https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/iPhoneOSKeys.html#//apple_ref/doc/uid/TP40009252-SW11
    - buildSettings > IPHONEOS_DEPLOYMENT_TARGET

# network

https://blogs.aaddevsup.xyz/2018/04/tracing-all-network-machine-traffic-using-mitmproxy-for-mac-osx/

# archives

- .pkg
    - aka: .xar || .pbzx
    - magic bytes: offset 0x0 = xar || pbzx
    - [!] app store payloads are encrypted
        - https://appleid.apple.com/auth/keys
- .yaa
    - https://wwws.nightwatchcybersecurity.com/2020/06/14/yaa-an-obscure-macos-compressed-file-format/

```bash
pkgutil --expand-full foo output/
xar -x -f foo -C output/
pbzx foo | cpio -idmu
# stream .pbzx files that are not wrapped in a .xar
pbzx -n foo | cpio -i
```

# automation

[GitHub \- facebook/idb: idb is a flexible command line interface for automating iOS simulators and devices](https://github.com/facebook/idb)

# unpack

[GitHub \- nrosenstein\-stuff/pbzx: Fork of the pbzx stream parser \(www\.tonymacx86\.com/general\-help/135458\-pbzx\-stream\-parser\.html\)](https://github.com/NiklasRosenstein/pbzx)

```bash
open -W _.xip
xip -x _.xip
```

# install

```bash
# Settings
networksetup
systemsetup

# IDE
xcode-select --install

# System Package Manager
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
grep -qi '/usr/local/bin' ~/.bash_profile || echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bash_profile
brew install git vim

# Language Package Manager
# Update from: ruby 2.0.0p648
# References: https://stackoverflow.com/questions/38194032/how-to-update-ruby-version-2-0-0-to-the-latest-version-in-mac-osx-yosemite
brew install ruby
echo 'export PATH="/usr/local/opt/ruby/bin:$PATH"' >> ~/.profile
echo 'export PATH="/usr/local/lib/ruby/gems/2.7.0/bin:$PATH"' >> ~/.profile
gem install bundler
gem install cocoapods
# ||
# Workaround for: SSL_connect returned=1 errno=0 state=SSLv2/v3 read server hello A: tlsv1 alert protocol version (https://rubygems.org/latest_specs.4.8.gz)
sudo gem install i18n -v '0.7.0' --no-ri --no-rdoc --source http://rubygems.org
sudo gem install minitest -v '< 4.9.0' --no-ri --no-rdoc --source http://rubygems.org
sudo gem install cocoapods --source http://rubygems.org

brew install carthage
```

- https://github.com/donnemartin/dev-setup
- https://github.com/nicolashery/mac-dev-setup
- https://github.com/boxen/our-boxen

# cocoapods

```bash
# Given `Podfile`
pod install
```

# xcode

- login
    - accounts > Apple IDs > [select entry]
- [Optional] Integrating Swift with Objective-C
    - Project navigator > [select project] > Build Settings > Swift Compiler - General > Objective-C Bridging Header
        - `#import "foo/bar.h"`
- [!] Bundle Identifier must be unique
    - `project.pbxproj`> PRODUCT_BUNDLE_IDENTIFIER
- test
    - product > destination > [iOS simulator || device]
    - Open Settings on F and navigate to General -> Device Management, then select your Developer App certificate to trust it.
- build .ipa
    - Project navigator > [select project] > general > signing > team
        - `project.pbxproj` > TargetAttributes > DevelopmentTeam
    - product > destination > [build only device]
    - product > archive
        - /Users/$USER/Library/Developer/Xcode/Archives/yyyy-mm-dd/foo.xcarchive
    - [enroll in apple developer program] > window > organizer > [select app] > distribute app
        - iOS App Store, Export
- errors
    - https://docs.jasonette.com/faq/

---

- https://stackoverflow.com/questions/32763288/ios-builds-ipa-creation-no-longer-works-from-the-command-line
- https://medium.com/xcblog/xcodebuild-deploy-ios-app-from-command-line-c6defff0d8b8

```bash
echo "{\"method\":\"app-store\"}" | plutil -convert xml1 -o /tmp/exportOptions.plist -- -

xcodebuild archive -project  ProjectPath/myApp.xcodeproj  -scheme myApp -configuration Debug -archivePath pathForArchiveFolder/myApp.xcarchive
# ||
xcodebuild -workspace myApp.xcworkspace \
    -scheme myApp \
    -destination generic/platform=iOS build
xcodebuild -workspace myApp.xcworkspace -scheme myApp -sdk iphoneos -configuration AppStoreDistribution archive -archivePath $PWD/build/myApp.xcarchive
xcodebuild -exportArchive -archivePath $PWD/build/myApp.xcarchive -exportOptionsPlist exportOptions.plist -exportPath $PWD/build
```

exportOptions.plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>app-store</string>
    <key>teamID</key>
    <string>YOUR_TEN_CHARACTER_TEAM_ID</string>
</dict>
</plist>
```

exportOptionsXcode9.plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>compileBitcode</key>
  <false/>
  <key>method</key>
  <string>ad-hoc</string>
  <key>provisioningProfiles</key>
  <dict>
    <key>my.bundle.idenifier</key>
    <string>My Provisioning Profile Name</string>
  </dict>
  <key>signingCertificate</key>
  <string>iPhone Distribution</string>
  <key>signingStyle</key>
  <string>manual</string>
  <key>stripSwiftSymbols</key>
  <true/>
  <key>teamID</key>
  <string>YOURTEAMID</string>
  <key>thinning</key>
  <string>&lt;none&gt;</string>
</dict>
</plist>
```

```bash
xcodebuild -help
```

# apple development program

- [!] Assigned devices page is not acessible
    - => free provisioning
        - :( device needs to be connected
        - https://stackoverflow.com/questions/44060482/xcode-8-3-xcode-9-0-refresh-provisioning-profile-devices
    - https://forums.developer.apple.com/thread/47746

# vm

SATA disk
```foo.vmx
smc.version = "0"
```
- https://techsviewer.com/install-macos-high-sierra-vmware-windows
- https://github.com/DrDonk/unlocker
    - Patches VMware to enable support for macOS
    - Downloads "VMware Tools"

### usb

- usb 2.0
- focus vmware before pluging in

```bash
grep -i 'found device.*apple.*vid.*pid' vmware.log
```

foo.vmx:

```
usb.quirks.device0 = "0x05ac:0x12a8 skip-reset, skip-refresh, skip-setconfig"
```

```
Unhandled Lockdown error (-2)
vmx| I125+ The specified device is in use by process:1188 /usr/lib/systemd/systemd-udevd on the host operating system. Continuing will detach the device from the host operating system.
vmx| I125+ The specified device is in use by process:12996 /usr/libexec/gvfsd-gphoto2 on the host operating system. Continuing will detach the device from the host operating system.
vmx| I125+ The specified device is in use by process:1729 /usr/sbin/usbmuxd on the host operating system. Continuing will detach the device from the host operating system.
vmx| W115: USBGL: failed to submit urb to device 146: Device or resource busy
```

```bash
for i in /usr/libexec/gvfs*; do sudo killall "$i"; done

# Rollback
/usr/libexec/gvfsd &disown
/usr/libexec/gvfsd-fuse /run/user/1000/gvfs -f &disown
/usr/libexec/gvfs-afc-volume-monitor &disown
/usr/libexec/gvfs-goa-volume-monitor &disown
/usr/libexec/gvfs-gphoto2-volume-monitor &disown
/usr/libexec/gvfs-mtp-volume-monitor &disown
/usr/libexec/gvfs-udisks2-volume-monitor &disown
```

vmware.log:

```log
2019-02-27T23:26:40.824Z| vmx| I125: USB: Connecting device desc:name:Apple\ iPhone vid:05ac pid:12a8 path:2/2 speed:high family:imaging serialnum:604ce5b1932c31c3ef5d7a033f6d5e75bf1ad12c arbRuntimeKey:9 quirks:slow-reconnect version:3 id:0x1000000905ac12a8
2019-02-27T23:26:40.844Z| vmx| I125: Policy_GetUSBDevAccess: checking usb devices at policy path: /vm/#_VMX/mvm/policyState/val/policySet/usbDevices/#
2019-02-27T23:26:40.844Z| vmx| I125: Policy_GetUSBDevAccess: allowConnect = YES
2019-02-27T23:26:40.844Z| vmx| I125: USBG: Quirks for device 05ac:12a8 (user-defined,skip-setconfig,skip-reset,skip-refresh)
2019-02-27T23:26:40.844Z| vmx| I125: USBG: Created 1000000905ac12a8
2019-02-27T23:26:40.951Z| vmx| I125: USBGL: Ignoring claim interface failure: device (fd=136), interface 0 doesn't exist
2019-02-27T23:26:40.968Z| vmx| I125: USBGL: Connected device 0x1000000905ac12a8 successfully
```

- https://developer.ridgerun.com/wiki/index.php?title=How_to_setup_and_use_USB/IP
- https://forums.virtualbox.org/viewtopic.php?f=35&t=82639
- https://stackoverflow.com/questions/36139020/macos-on-vmware-doesnt-recognize-ios-device
    - https://kb.vmware.com/s/article/774?lang=en_US
    - https://askubuntu.com/questions/645/how-do-you-reset-a-usb-device-from-the-command-line/661#661

# iOS databases

- Contacts: `var/mobile/Library/AddressBook/AddressBook.sqlitedb`
- Calls: `var/mobile/Library/CallHistoryDB/CallHistory.storedata`
- SMS: `var/mobile/Library/SMS/sms.db`
- Safari: `var/mobile/Library/Safari/History.db`
- Google Maps: `var/mobile/Library/Maps/History.plist`
- Apple Maps: 
    - `var/mobile/Library/Maps/Bookmarks.plist`
    - `var/mobile/Containers/Shared/AppGroup/group.com.apple.Maps/Maps/MapsSync_0.0.1`
    - `var/mobile/Containers/Shared/AppGroup/group.com.apple.Maps/Maps/MapsSync_0.0.1_deviceLocalCache.db`
    - iOS13: `var/mobile/Library/Maps/GeoHistory.mapsdata`
    - iOS8: `var/mobile/Library/Maps/History.mapsdata`

- BLOB extraction: [GitHub \- threeplanetssoftware/sqlite\_miner: A script to mine SQLite databases for hidden gems that might be overlooked](https://github.com/threeplanetssoftware/sqlite_miner)

# iOS packaging, upload

### macos

```bash
/Applications/Xcode.app/Contents/Applications/Application\ Loader.app/Contents/Frameworks/ITunesSoftwareService.framework/Support/altool --upload-app -f "CLI.ipa" -u $USERNAME -p $PASSWORD
```

### linux

```bash
# install via libimobiledevice
ideviceinstaller -i _.ipa
```

# search

- [mdfind Man Page \- macOS \- SS64\.com](https://ss64.com/osx/mdfind.html)

# service management

```bash
launchd
```

# dict

- [GitHub \- josh\-/DictionaryPlusPlus: Dictionary\+\+ is a simple interface to iOS&\#39;s system dictionary\.](https://github.com/josh-/DictionaryPlusPlus)

- MobileAssetError Unable to copy asset attributes
- MobileAssetError Unable to copy asset information from https://mesu.apple.com/assets for asset type com.apple.MobileAsset.TextInput.SpellChecker
    - => ? simulator network/wifi access
    - http://mesu.apple.com/assets/com_apple_MobileAsset_TextInput_SpellChecker/com_apple_MobileAsset_TextInput_SpellChecker.xml
    - https://stackoverflow.com/questions/43419437/errors-ios-10-unable-to-copy-asset-information-from-https-mesu-apple-com-ass?rq=1
    - https://stackoverflow.com/questions/39868842/error-in-ios-10-unable-to-copy-asset-information-from-https-mesu-apple-com-a
    - https://stackoverflow.com/a/39581193
        - https://llvm.org/svn/llvm-project/lldb/trunk/source/Plugins/Platform/MacOSX/PlatformDarwin.cpp

- [GitHub \- willhains/Kotoba: Quickly search the built\-in iOS dictionary to see definitions of words\. Collect words you want to remember\.](https://github.com/willhains/Kotoba)

# docs

- https://developer.apple.com/documentation/foundation/nsstring

# constraints

- iOS version => XCode version => macos version
    - macos version = `system_profiler SPSoftwareDataType`
    - https://xcodereleases.com/
    - https://en.wikipedia.org/wiki/Xcode#Xcode_7.0_-_10.x_(since_Free_On-Device_Development)
- swift version => XCode version
    - 2 => 7.x
    - 3 => 8.x
    - 4 => 9.x
    - 4.2 => 10.x
    - 5.1 => 11.x
    - 5.3 => 12.x
- linux => macos vm
    - vmware - best compatibility
    - || virtualbox - usb 3 passthrough compatibility => macos version
- carthage => Xcode.app 10.0

# hardware info

```bash
ioreg -lw0
```

# syscall / signal tracing

```bash
# Workaround for: dtrace: system integrity protection is on, some features will not be available
csrutil enable --without dtrace
# ||
csrutil disable

# Workaround for: csrutil: failed to modify system integrity configuration. This tool needs to be executed from the Recovery OS.
# - Boot to Recovery OS by restarting your machine and holding down the Command and R keys at startup.

# ~= strace
sudo dtruss -f -p 43334
```

- http://www.brendangregg.com/DTrace/dtruss_example.txt
- [Behind the scenes of shell IO redirection &\#8211; Zoned Out](https://rhardih.io/2017/11/behind-the-scenes-of-shell-io-redirection/)
    - [Reboot OS X in recovery mode](https://support.apple.com/en-us/HT201314)

# jailbreak

- change root password
- update hosts file

- https://www.reddit.com/r/jailbreak/wiki/index

### iOS 10

- https://h3lix.tihmstar.net/
- https://www.reddit.com/r/jailbreak/wiki/ios10jailbreakhelp

# firewall

- [GitHub \- objective\-see/LuLu: LuLu is the free macOS firewall](https://github.com/objective-see/LuLu)

# unified logging

Since: macOS 10.12 Sierra

```bash
log stream
log stream --process `pgrep -f /usr/local/bin/foo` --info --debug
log show --predicate 'process == "foo"' --last 1h --info --debug
log collect --device
log collect device-name="foo's iPhone"
log collect device-udid=foo
```

# dissassemly

```bash
otool -tV /usr/libexec/foo
```

# classic

- Debug
    - http://basalgangster.macgui.com/RetroMacComputing/The_Long_View/Entries/2010/5/1_Resources_and_Resource_Editors.html
- MacOS 7
    - https://www.emaculation.com/doku.php/basiliskii_osx_setup
        1. DiskTools_MacOS7.img
        2. OS753InstallerParts.dsk
        3. foo.img
- MacOS 9
    ```bash
    qemu-img create -f qcow2 foo.img 4G
    qemu-system-ppc -L pc-bios -boot d -M mac99,via=pmu -m 512 \
        -hda foo.img \
        -cdrom install.iso
    # Format: CD > Utilities > Drive Setup > Initialize
    qemu-system-ppc -L pc-bios -boot d -M mac99,via=pmu -m 512 \
        -drive file=foo.img,format=qcow2,media=disk \
        -netdev user,id=network01 -device sungem,netdev=network01 \
        -device VGA,edid=on
    ```
