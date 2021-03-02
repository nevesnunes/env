# +

- https://docs.docker.com/toolbox/toolbox_install_windows/
- docker swarm - automatic rollback
    - [Can&\#39;t rollback service automatically after update  · Issue \#33427 · moby/moby · GitHub](https://github.com/moby/moby/issues/33427)
- [GitHub \- google/cadvisor: Analyzes resource usage and performance characteristics of running containers\.](https://github.com/google/cadvisor)

- https://gtfobins.github.io/gtfobins/docker/
    ```bash
    sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
    ```

```bash
# Given: yi moby-engine
sudo dockerd
# ||
sudo systemctl start docker.service

docker pull ubuntu
docker run ubuntu bash -c "apt-get -y install nginx"
docker run -it ubuntu bash

docker container ls
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

# References

- https://docs.docker.com/articles/dockerfile_best-practices/
- http://crosbymichael.com/dockerfile-best-practices.html
- https://github.com/wsargent/docker-cheat-sheet

# Dockerfile

https://github.com/LiveOverflow/pwn_docker_example/blob/master/challenge/Dockerfile

# create vm for containers

[GitHub \- docker/machine: Machine management for a container\-centric world](https://github.com/docker/machine)

```bash
docker-machine create -d virtualbox default
eval "$(docker-machine env default)"
```

# permissions

```bash
mkdir -p /data1/Downloads
docker run -it -v /data1/Downloads:/Downloads ubuntu bash
# ||
docker volume create \
    --driver local \
    --name hello \
    --opt type=none \
    --opt device=/data1/Downloads \
    --opt o=uid=root,gid=root \
    --opt o=bind 
docker run -it -v hello:/Downloads ubuntu bash
# || Given: selinux enabled
docker run -it -v hello:/Downloads:z ubuntu bash
```

### avoiding root

```
DOCKER_OPTS="--userns-remap=1000:1000"
```

# build

```bash
# Given: $PWD/Dockerfile
docker build . --tag whipper/whipper
docker images | grep 'whipper/whipper'
# Cleanup:
docker images --filter "dangling=true" -q --no-trunc | xargs -I{} docker rmi {}
# ||
docker image prune -af
```

# architeture, e.g. 32bit vs 64bit

```
standard_init_linux.go:190: exec user process caused "exec format error" 
```

Reported architecture inside container is from host
=> ENTRYPOINT ["linux32"]
    - https://stackoverflow.com/questions/26490935/how-to-fake-cpu-architecture-in-docker-container

# container path

- https://stackoverflow.com/questions/32070113/how-do-i-change-the-default-docker-container-location
- https://forums.docker.com/t/how-do-i-change-the-docker-image-installation-directory/1169

# system info - cpu architecture

```bash
docker inspect
```
    - https://docs.docker.com/engine/reference/commandline/inspect/

# persistence, updates

- https://stackoverflow.com/questions/18496940/how-to-deal-with-persistent-storage-e-g-databases-in-docker
- https://thenewstack.io/methods-dealing-container-storage/

# binding user ids

- https://github.com/lemire/docker_programming_station
- https://seravo.fi/2019/align-user-ids-inside-and-outside-docker-with-subuser-mapping

# Multiple containers

```bash
docker network create --driver bridge
docker run --network=foo --name=bar
```

- https://stackoverflow.com/a/48243640
- https://dev.to/abiodunjames/why-docker-creating-a-multi-container-application-with-docker--1gpb
- https://docs.docker.com/compose/overview/

# Delete containers

```bash
docker system purge -af
```

```batch
@echo off
FOR /f "tokens=*" %%i IN ('docker ps -aq') DO docker rm %%i
FOR /f "tokens=*" %%i IN ('docker images --format "{{.ID}}"') DO docker rmi %%i
```

```ps1
docker ps -aq | foreach {docker rm -f $_}
docker images -aq | foreach {docker rmi -f $_}
```

# Nesting, docker-in-docker

bind-mounting the host machine's Docker socket in the container

**TODO**

# debug processes across pid namespaces

```bash
# against host
docker run -it --rm --pid=host myhtop

# against another container
docker run --name my_redis -d redis
docker run -it --pid=container:my_redis my_strace_docker_image bash
strace -p 1
```

https://docs.docker.com/engine/reference/run/#pid-settings---pid

# ip address

```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' CONTAINER_ID_OR_NAME
docker ps \
    | awk '/[0-9a-f]{12}/{print $1}' \
    | xargs -I{} docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {}
```
