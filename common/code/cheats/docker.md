# +

https://docs.docker.com/toolbox/toolbox_install_windows/
docker swarm - automatic rollback
    https://github.com/moby/moby/issues/33427

```bash
# yi moby-engine
sudo dockerd
# ||
sudo systemctl start docker.service

docker pull ubuntu
docker run ubuntu bash -c "apt-get -y install nginx"
docker run -it ubuntu bash

docker ps -l
docker commit 5976e4ae287c ubuntu-nginx
docker images
docker run ubuntu-nginx whereis nginx

# From Dockerfile
docker build -t container_name .
docker run container_name

# Detached
docker run -d IMAGE
docker logs -f CONTAINER_ID_OR_NAME
docker exec -it CONTAINER_ID_OR_NAME /bin/bash
docker attach CONTAINER_ID_OR_NAME
```

---

```bash
# https://packages.ubuntu.com/
update-dlocatedb
dlocate
apt-cache search package_name
dpkg-query -L package_name
dpkg-query -S file_name

rpm -ql package_name

apt-get install apt-file
apt-file update
apt-file find file_name
apt-file search file_name
apt-file list package_name

dnf provides file_name
```

# permissions

```bash
mkdir -p /data1/Downloads
docker volume create --driver local --name hello --opt type=none --opt device=/data1/Downloads --opt o=uid=root,gid=root --opt o=bind
docker run -i -v hello:/Downloads ubuntu bash
# || with selinux
docker run -i -v hello:/Downloads:z ubuntu bash
```

# build

```bash
# Given: $PWD/Dockerfile
docker build . --tag whipper/whipper
# Then:
docker images | grep 'whipper/whipper'
```

# architeture, e.g. 32bit vs 64bit

```
standard_init_linux.go:190: exec user process caused "exec format error" 
```

Reported architecture inside container is from host
=> ENTRYPOINT ["linux32"]
-- https://stackoverflow.com/questions/26490935/how-to-fake-cpu-architecture-in-docker-container

# container path

https://stackoverflow.com/questions/32070113/how-do-i-change-the-default-docker-container-location
https://forums.docker.com/t/how-do-i-change-the-docker-image-installation-directory/1169

# system info - cpu architecture

docker inspect
https://docs.docker.com/engine/reference/commandline/inspect/

# Multiple containers

docker network create --driver bridge
docker run --network=foo --name=bar

https://stackoverflow.com/a/48243640
https://dev.to/abiodunjames/why-docker-creating-a-multi-container-application-with-docker--1gpb
https://docs.docker.com/compose/overview/
