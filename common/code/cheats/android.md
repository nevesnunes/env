# decompiler

https://ibotpeaches.github.io/Apktool
http://www.javadecompilers.com/apk
http://www.decompileandroid.com/

[GitHub \- androguard/androguard: Reverse engineering, Malware and goodware analysis of Android applications \.\.\. and more \(ninja !\)](https://github.com/androguard/androguard)
    https://code.google.com/archive/p/elsim/wikis/Similarity.wiki#Android
    https://www.phrack.org/issues.html?issue=68&id=15#article

# emulation

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
adb start-server
adb install foo.apk

/snap/bin/anbox launch --package=org.anbox.appmgr --component=org.anbox.appmgr.AppViewActivity

~/opt/android-studio/bin/studio.sh
```

# issues

[Difficult to install on Fedora system · Issue \#771 · anbox/anbox · GitHub](https://github.com/anbox/anbox/issues/771)
[Kernel oops caused by ashmem\_mem on Fedora 31 running 5\.3\.16\-300\.fc31\.x86\_64 · Issue \#41 · anbox/anbox\-modules · GitHub](https://github.com/anbox/anbox-modules/issues/41)

# case studies

https://upbhack.de/posts/2018/06/writeup-shallweplayagame-from-google-ctf-qualifier-2018/


