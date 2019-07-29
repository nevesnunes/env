# +

networksetup
systemsetup

# automation

https://github.com/facebook/idb

# profiling

system_profiler SPSoftwareDataType

# unpack

https://github.com/NiklasRosenstein/pbzx

```bash
open -W _.xip
xip -x _.xip
```

# install

```bash
xcode-select --install

# ||
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
grep -qi '/usr/local/bin' ~/.bash_profile || echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bash_profile
brew install git vim
```

https://github.com/donnemartin/dev-setup
https://github.com/nicolashery/mac-dev-setup
https://github.com/boxen/our-boxen

# xcode

test
    product > destination > [iOS simulator || device]
    Open Settings on F and navigate to General -> Device Management, then select your Developer App certificate to trust it.
build .ipa
    [select project] > general > signing > team
    product > destination > [build only device]
    product > archive
        /Users/fn/Library/Developer/Xcode/Archives/yyyy-mm-dd/foo.xcarchive
    [enroll in apple developer program] > window > organizer > [select app] > distribute app
        iOS App Store, Export
errors
    https://docs.jasonette.com/faq/

---

https://stackoverflow.com/questions/32763288/ios-builds-ipa-creation-no-longer-works-from-the-command-line
https://medium.com/xcblog/xcodebuild-deploy-ios-app-from-command-line-c6defff0d8b8

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

```exportOptions.plist 
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

```exportOptionsXcode9.plist
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

xcodebuild -help

# apple development program

/!\ Assigned devices page is not acessible
    => free provisioning
        :( device needs to be connected
        https://stackoverflow.com/questions/44060482/xcode-8-3-xcode-9-0-refresh-provisioning-profile-devices
    https://forums.developer.apple.com/thread/47746

# vm

SATA disk
```foo.vmx
smc.version = "0"
```
https://techsviewer.com/install-macos-high-sierra-vmware-windows
https://github.com/DrDonk/unlocker

### usb

usb 2.0
focus vmware before pluging in

grep -i 'found device.*apple.*vid.*pid' vmware.log
```foo.vmx
usb.quirks.device0 = "0x05ac:0x12a8 skip-reset, skip-refresh, skip-setconfig"
```

Unhandled Lockdown error (-2)
vmx| I125+ The specified device is in use by process:1188 /usr/lib/systemd/systemd-udevd on the host operating system. Continuing will detach the device from the host operating system.
vmx| I125+ The specified device is in use by process:12996 /usr/libexec/gvfsd-gphoto2 on the host operating system. Continuing will detach the device from the host operating system.
vmx| I125+ The specified device is in use by process:1729 /usr/sbin/usbmuxd on the host operating system. Continuing will detach the device from the host operating system.
vmx| W115: USBGL: failed to submit urb to device 146: Device or resource busy
```bash
for i in /usr/libexec/gvfs*; do sudo killall "$i"; done
```

/run/media/fn/MEMUP\ 1TO/FN-NUX/vmware/macOS\ 10.12/vmware-2.log
2019-02-27T23:26:40.824Z| vmx| I125: USB: Connecting device desc:name:Apple\ iPhone vid:05ac pid:12a8 path:2/2 speed:high family:imaging serialnum:604ce5b1932c31c3ef5d7a033f6d5e75bf1ad12c arbRuntimeKey:9 quirks:slow-reconnect version:3 id:0x1000000905ac12a8
2019-02-27T23:26:40.844Z| vmx| I125: Policy_GetUSBDevAccess: checking usb devices at policy path: /vm/#_VMX/mvm/policyState/val/policySet/usbDevices/#
2019-02-27T23:26:40.844Z| vmx| I125: Policy_GetUSBDevAccess: allowConnect = YES
2019-02-27T23:26:40.844Z| vmx| I125: USBG: Quirks for device 05ac:12a8 (user-defined,skip-setconfig,skip-reset,skip-refresh)
2019-02-27T23:26:40.844Z| vmx| I125: USBG: Created 1000000905ac12a8
2019-02-27T23:26:40.951Z| vmx| I125: USBGL: Ignoring claim interface failure: device (fd=136), interface 0 doesn't exist
2019-02-27T23:26:40.968Z| vmx| I125: USBGL: Connected device 0x1000000905ac12a8 successfully

https://developer.ridgerun.com/wiki/index.php?title=How_to_setup_and_use_USB/IP
https://forums.virtualbox.org/viewtopic.php?f=35&t=82639
https://stackoverflow.com/questions/36139020/macos-on-vmware-doesnt-recognize-ios-device
    https://kb.vmware.com/s/article/774?lang=en_US
    https://askubuntu.com/questions/645/how-do-you-reset-a-usb-device-from-the-command-line/661#661

# ios packaging, upload

### macos

/Applications/Xcode.app/Contents/Applications/Application\ Loader.app/Contents/Frameworks/ITunesSoftwareService.framework/Support/altool --upload-app -f "CLI.ipa" -u $USERNAME -p $PASSWORD

### linux

install via libimobiledevice

```bash
ideviceinstaller -i _.ipa
```

# search

https://ss64.com/osx/mdfind.html

# service management

launchd

# dict

https://github.com/josh-/DictionaryPlusPlus
Bundle Identifier: joshparnham.Dictionary--

MobileAssetError Unable to copy asset attributes
MobileAssetError Unable to copy asset information from https://mesu.apple.com/assets for asset type com.apple.MobileAsset.TextInput.SpellChecker
    => ? simulator network/wifi access
    http://mesu.apple.com/assets/com_apple_MobileAsset_TextInput_SpellChecker/com_apple_MobileAsset_TextInput_SpellChecker.xml
    https://stackoverflow.com/questions/43419437/errors-ios-10-unable-to-copy-asset-information-from-https-mesu-apple-com-ass?rq=1
    https://stackoverflow.com/questions/39868842/error-in-ios-10-unable-to-copy-asset-information-from-https-mesu-apple-com-a
    https://stackoverflow.com/a/39581193
        https://llvm.org/svn/llvm-project/lldb/trunk/source/Plugins/Platform/MacOSX/PlatformDarwin.cpp

https://github.com/willhains/Kotoba

# docs

https://developer.apple.com/documentation/foundation/nsstring

# constraints

iOS version => XCode version => macos version
linux => macos vm
vm
    vmware - best compatibility
    || virtualbox - usb 3 passthrough compatibility => macos version

# profiling

system_profiler SPSoftwareDataType

# unpack

https://github.com/NiklasRosenstein/pbzx

```bash
open -W _.xip
xip -x _.xip
```

# install

https://github.com/donnemartin/dev-setup
https://github.com/nicolashery/mac-dev-setup
https://github.com/boxen/our-boxen

```bash
xcode-select --install

/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
grep -qi '/usr/local/bin' ~/.bash_profile || echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bash_profile
brew install git vim
```

# ios packaging

vm - usb 3 may not work
    https://developer.ridgerun.com/wiki/index.php?title=How_to_setup_and_use_USB/IP
    https://forums.virtualbox.org/viewtopic.php?f=35&t=82639
linux - install via libimobiledevice

# dict

https://github.com/josh-/DictionaryPlusPlus
https://github.com/willhains/Kotoba
