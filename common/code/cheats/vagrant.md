# lifecycle

```bash
# lifecycle - create / boot
# cd to dir with `Vagrantfile`
vagrant up

# lifecycle - run
vagrant ssh
docker ps

vagrant pause
vagrant resume

# lifecycle - kill / shutdown
vagrant halt
vagrant destroy
```

# bootstrap

```bash
vagrant plugin install vagrant-docker-compose
vagrant plugin install vagrant-disksize
vagrant plugin install vagrant-vbguest

mkdir -p ~/code/config/vagrant
cd ~/code/config/vagrant
git clone https://gist.github.com/7593677f6d03285236c8f0391f1a78c2.git ubuntu-docker
cd ubuntu-docker
```

https://github.com/dduportal/alpine2docker
https://github.com/rankinjl/vagrant-docker-ubuntu
https://github.com/webdevops/vagrant-docker-vm

```bash
vagrant box add alpine2docker-1.8.0 file://"$(cygpath -w "$(realpath ./alpine2docker-1.8.0.box)")"
vagrant init alpine2docker-1.8.0
vagrant up
# == ssh alpine@127.0.0.1 -p 2222
vagrant ssh

# Validation
vagrant box list
```

```Vagrantfile
# Solves error: mounting /dev/loop0 on /mnt failed: Invalid argument
config.vbguest.auto_update = false
```

https://wiki.alpinelinux.org/wiki/VirtualBox_shared_folders

# apply changes to box

```bash
vagrant halt
# ...
vagrant reload
```

# windows guest

config.vm.communicator = "winrm"

- vagrant ssh => ssh server in guest
- vagrant powershell => windows host
- vagrant rdp => cross-platform, windows guest

https://codeblog.dotsandbrackets.com/vagrant-windows/

# disable other hypervisors

```ps1
# [virtual machine \- virtualbox Raw\-mode is unavailable courtesy of Hyper\-V windows 10 \- Stack Overflow](https://stackoverflow.com/a/51200509)
bcdedit /set hypervisorlaunchtype off
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
```

```bash
echo 'blacklist kvm-intel' >> /etc/modprobe.d/blacklist.conf
```

<!-- @Validation -->
```bash
lsmod | grep kvm
# Pick module without dependencies
```

# provisioning multiple providers

https://blog.codeship.com/packer-vagrant-tutorial/

# debug

```
"builders": [{
 "headless" : false,
 "ssh_wait_timeout": "1000s",
}]
```

```bash
# rdp to 127.0.0.1:$image_rdp_port
# ||
ssh -nNTvv -L 13080:$image_ip:22 $image_user@$image_ip
```


