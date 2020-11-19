# decompiler

[GitHub \- pxb1988/dex2jar: Tools to work with android \.dex and java \.class files](https://github.com/pxb1988/dex2jar)
[GitHub \- skylot/jadx: Dex to Java decompiler](https://github.com/skylot/jadx)
http://www.javadecompilers.com/apk
http://www.decompileandroid.com/

[GitHub \- androguard/androguard: Reverse engineering, Malware and goodware analysis of Android applications \.\.\. and more \(ninja !\)](https://github.com/androguard/androguard)
    https://code.google.com/archive/p/elsim/wikis/Similarity.wiki#Android
    https://www.phrack.org/issues.html?issue=68&id=15#article

# dissassembler

https://ibotpeaches.github.io/Apktool/install/

# emulation

https://github.com/aind-containers/aind
    :) exposes VNC
https://www.android-x86.org/
    https://dotsrc.dl.osdn.net/osdn/android-x86/71931/android-x86_64-9.0-r1.iso
    https://www.vimalin.com/blog/install-android-x86-in-vmware-fusion/
https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/android/docs/ANDROID-QEMU-PIPE.TXT

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

https://docs.anbox.io/userguide/install.html
    https://docs.anbox.io/userguide/install_kernel_modules.html
https://github.com/Deadolus/android-studio-docker

### container

https://github.com/aind-containers/aind

# dynamic instrumentation

- ~/code/snippets/frida/android.py
    - https://bananamafia.dev/post/r2frida-1/
```bash
# https://github.com/frida/frida/releases
adb push frida-server /data/local/tmp
```

# class loading

```java
DexClassLoader dexClassLoader = new DexClassLoader(path_to_dex, null, null, parent_class);
Class dynamic_class = dexClassLoader.loadClass("DynamicClass");
Method method = dynamic_class.getMethod("method1");
```

https://developer.android.com/reference/dalvik/system/DexClassLoader

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

https://www.fosslinux.com/13176/how-to-install-and-run-android-apps-on-ubuntu-using-anbox.htm

# running apps

```bash
/snap/bin/anbox launch --package=org.anbox.appmgr --component=org.anbox.appmgr.AppViewActivity
adb start-server
adb devices
adb install foo.apk
# || Specific device
adb -s emulator-5555 install foo.apk

~/opt/android-studio/bin/studio.sh
```

# debug

```bash
# Find package name, take $pid
ps | grep -i flag
# u0_a49    711   30    1043872 80604          0 0000000000 S lu.hack.Flagdroid

# Use main class
# e.g. `public class MainActivity extends AppCompatActivity`
am start -D -e debug true -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n "lu.hack.Flagdroid/.MainActivity"

adb forward --remove-all
adb forward tcp:8012 jdwp:$pid
jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8012
```

https://stackoverflow.com/questions/25477424/adb-shell-su-works-but-adb-root-does-not
[Can i root anbox device? · Issue \#209 · anbox/anbox · GitHub](https://github.com/anbox/anbox/issues/209)

https://asantoso.wordpress.com/2009/09/26/using-jdb-with-adb-to-debugging-of-android-app-on-a-real-device/
https://source.android.com/devices/tech/debug/gdb

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

- https://upbhack.de/posts/2018/06/writeup-shallweplayagame-from-google-ctf-qualifier-2018/
- https://medium.com/bugbountywriteup/recovering-a-lost-phone-number-using-hacker-mindset-5e7e7a30edbd
