# decompiler

- [GitHub \- JesusFreke/smali: smali/baksmali](https://github.com/JesusFreke/smali)
- [GitHub \- pxb1988/dex2jar: Tools to work with android \.dex and java \.class files](https://github.com/pxb1988/dex2jar)
    - https://github.com/DexPatcher/dex2jar/releases/
- [GitHub \- skylot/jadx: Dex to Java decompiler](https://github.com/skylot/jadx)
- [GitHub \- Storyyeller/enjarify](https://github.com/Storyyeller/enjarify)
- http://www.javadecompilers.com/apk
- http://www.decompileandroid.com/

- [GitHub \- MobSF/Mobile\-Security\-Framework\-MobSF: Mobile Security Framework \(MobSF\) is an automated, all\-in\-one mobile application \(Android/iOS/Windows\) pen\-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis\.](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [GitHub \- androguard/androguard: Reverse engineering, Malware and goodware analysis of Android applications \.\.\. and more \(ninja !\)](https://github.com/androguard/androguard)
    - https://code.google.com/archive/p/elsim/wikis/Similarity.wiki#Android
    - https://www.phrack.org/issues.html?issue=68&id=15#article
-[GitHub \- enovella/fridroid\-unpacker: Defeat Java packers via Frida instrumentation](https://github.com/enovella/fridroid-unpacker)

- [0x05j-testing-resiliency-against-reverse-engineering](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05j-testing-resiliency-against-reverse-engineering)
- [Decompiling Google Safety Net \- Jared Rummler](https://jaredrummler.com/2017/03/07/decompiling-google-safety-net/)

# debugging

- [GitHub \- JesusFreke/smalidea: smalidea is a smali language plugin for IntelliJ IDEA](https://github.com/JesusFreke/smalidea)
- [GitHub \- bannsec/enableAPKDebugging: Application to simplify apk\-&gt;apk w/ debugging enabled](https://github.com/bannsec/enableAPKDebugging)
- [GitHub \- iGio90/Dwarf: Full featured multi arch/os debugger built on top of PyQt5 and frida](https://github.com/iGio90/Dwarf)
- [GitHub \- iGio90/frida\-onload: Frida module to hook module initializations on android](https://github.com/iGio90/frida-onload)

# emulation

- android-studio
    - :) up to date API level support
    - https://developer.android.com/studio/command-line/variables
- https://www.android-x86.org/
    - :) Bluetooth, G-sensor support
    - https://osdn.net/projects/android-x86/releases
    - https://www.android-x86.org/documentation/virtualbox.html
    - https://www.vimalin.com/blog/install-android-x86-in-vmware-fusion/
- https://github.com/aind-containers/aind
    - :) exposes VNC
- https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/android/docs/ANDROID-QEMU-PIPE.TXT

### anbox

```bash
# Kernel dependencies
apt -y install software-properties-common \
    && add-apt-repository -y ppa:morphis/anbox-support \
    && apt -y update \
    && apt -y install linux-headers-generic anbox-modules-dkms \
    && modprobe ashmem_linux \
    && modprobe binder_linux

# Snap
apt -y install snapd \
    && snap install --devmode --beta anbox
```

- https://docs.anbox.io/userguide/install.html
    - https://docs.anbox.io/userguide/install_kernel_modules.html
- https://github.com/Deadolus/android-studio-docker

### container

- https://github.com/aind-containers/aind

# extracting / unpacking

```bash
apktool d -r -s foo.apk
```

# patching / repacking / rebuild

```bash
# build
apktool b -f -d foo

# sign
keytool -genkey -v -keystore foo.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore foo.keystore foo.apk alias_name
jarsigner -verify -verbose -certs foo.apk

# align
./zipalign -v 4 foo.apk foo-aligned.apk
```

- add logging to smali bytecode
    - decompile example project to obtain logging instructions
    - https://yepoleb.github.io/blog/2021/08/18/reverse-engineering-the-check-at-android-app/

# dynamic instrumentation

```bash
# https://github.com/frida/frida/releases
adb push frida-server /data/local/tmp
```

- ~/code/snippets/frida/android.py
    - https://bananamafia.dev/post/r2frida-1/
- https://github.com/Areizen/JNI-Frida-Hook

- https://github.com/Project-ARTist/ARTist
    - https://saarsec.rocks/2018/11/27/Gunshop.html

# class loading

```java
DexClassLoader dexClassLoader = new DexClassLoader(path_to_dex, null, null, parent_class);
Class dynamic_class = dexClassLoader.loadClass("DynamicClass");
Method method = dynamic_class.getMethod("method1");
```

- https://developer.android.com/reference/dalvik/system/DexClassLoader

# development

### android studio

```bash
apt -y install openjdk-11-jdk android-tools-adb
mkdir -p ~/opt \
    && cd ~/opt \
    && wget https://dl.google.com/dl/android/studio/ide-zips/4.0.1.0/android-studio-ide-193.6626763-linux.tar.gz -O android-studio.tar.gz \
    && tar xzvf android-studio.tar.gz \
    && rm android-studio.tar.gz
```

- https://www.fosslinux.com/13176/how-to-install-and-run-android-apps-on-ubuntu-using-anbox.htm

# download apps

- https://f-droid.org/en/packages/com.aurora.store/
- https://f-droid.org/en/packages/com.aurora.adroid/
- https://apkmirror.com/
- https://apkpure.com/
- https://acmarket.net/download.html
- https://archive.org/details/apkarchive

### Validation

```bash
# Verify certificate
# Preconditions: Extracted `foo.apk`
keytool -printcert -file META-INF\CERT.RSA
# ||
keytool -printcert -jarfile "foo.apk"
# ||
./android-sdk/build-tools/29.0.2/apksigner verify --verbose --print-certs "foo.apk"
```

- https://f-droid.org/en/docs/Release_Channels_and_Signing_Keys/

# running apps

```bash
# anbox
/snap/bin/anbox launch --package=org.anbox.appmgr --component=org.anbox.appmgr.AppViewActivity
adb start-server
adb devices
adb install foo.apk
# || Specific device
adb -s emulator-5555 install foo.apk

# android-x86
# Preconditions:
# - On VirtualBox: Use bridged network adapter
# - On guest: Use virtwifi connection with static ip
adb kill-server
adb connect 192.168.1.4:5555
# * daemon not running; starting now at tcp:5037
# * daemon started successfully
# connected to 192.168.1.4:5555
ADBHOST=192.168.1.4 adb push ./foo /sdcard
ADBHOST=192.168.1.4 adb install ./foo.apk

~/opt/android-studio/bin/studio.sh
```

### network access

```bash
wget https://raw.githubusercontent.com/anbox/anbox/master/scripts/anbox-bridge.sh
mkdir -p /usr/lib/anbox/
mv anbox-bridge.sh /usr/lib/anbox/
chmod +x /usr/lib/anbox/anbox-bridge.sh
chown root /usr/lib/anbox/anbox-bridge.sh
printf '
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

int main(void) {
	setuid(0);
    char buf[512];
	sprintf(buf, "/usr/lib/anbox/anbox-bridge.sh %s", "start");
	system((char *)buf);
}
' | gcc -o anbox-bridge -x c -
mv anbox-bridge /usr/local/bin
chmod u+s /usr/local/bin/anbox-bridge
chown root /usr/local/bin/anbox-bridge
```

# debug

```bash
adb shell
# Find package name, take $pid
ps -A | grep -i flag
# u0_a49    711   30    1043872 80604          0 0000000000 S lu.hack.Flagdroid

# Use main class
# e.g. `public class MainActivity extends AppCompatActivity`
am start -D -e debug true -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n "lu.hack.Flagdroid/.MainActivity"

adb forward --remove-all
adb forward tcp:8012 jdwp:$pid
jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8012
```

- https://stackoverflow.com/questions/25477424/adb-shell-su-works-but-adb-root-does-not
- [Can i root anbox device? · Issue \#209 · anbox/anbox · GitHub](https://github.com/anbox/anbox/issues/209)

- https://asantoso.wordpress.com/2009/09/26/using-jdb-with-adb-to-debugging-of-android-app-on-a-real-device/
- https://source.android.com/devices/tech/debug/gdb

### native

```bash
ndk-gdb --start --verbose --force
```

# root

```bash
sudo /snap/bin/anbox.shell
```

# virtual device

```bash
sudo /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager 'system-images;android-30;google_apis_playstore;x86_64'
/opt/android-sdk/cmdline-tools/latest/bin/avdmanager create avd -n osint -d 10 -k 'system-images;android-30;google_apis_playstore;x86_64'
ANDROID_SDK_ROOT=/opt/android-sdk /opt/android-sdk/emulator/emulator @osint
```

# filesystem hierarchy

- https://android.googlesource.com/platform/system/core/+/master
    - rootdir/init.rc
    - sdcard/
    - system/

# issues

- [Difficult to install on Fedora system · Issue \#771 · anbox/anbox · GitHub](https://github.com/anbox/anbox/issues/771)
- [Kernel oops caused by ashmem\_mem on Fedora 31 running 5\.3\.16\-300\.fc31\.x86\_64 · Issue \#41 · anbox/anbox\-modules · GitHub](https://github.com/anbox/anbox-modules/issues/41)

# case studies

- [GitHub \- rewanthtammana/Damn\-Vulnerable\-Bank: Damn Vulnerable Bank is designed to be an intentionally vulnerable android application\. This provides an interface to assess your android application security hacking skills\.](https://github.com/rewanthtammana/Damn-Vulnerable-Bank)
- https://upbhack.de/posts/2018/06/writeup-shallweplayagame-from-google-ctf-qualifier-2018/
- https://medium.com/bugbountywriteup/recovering-a-lost-phone-number-using-hacker-mindset-5e7e7a30edbd
