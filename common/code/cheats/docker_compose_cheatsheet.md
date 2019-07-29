---
title: Docker Compose Cheatsheet
subtitle: Quick reference for Docker Compose commands and config files
author: Jon LaBelle
date: April 7, 2019
source: https://jonlabelle.com/snippets/view/markdown/docker-compose-cheatsheet
---

## Basic config example

```yml
# docker-compose.yml
version: '3'

services:
  web:
    build: .
    # build from Dockerfile
    context: ./Path
    dockerfile: Dockerfile
    ports:
     - "5000:5000"
    volumes:
     - .:/code
  redis:
    image: redis
```

## Common commands

```bash
# Starts existing containers for a service.
docker-compose start

# Stops running containers without removing them.
docker-compose stop

# Pauses running containers of a service.
docker-compose pause

# Unpauses paused containers of a service.
docker-compose unpause

# Lists containers.
docker-compose ps

# Builds, (re)creates, starts, and attaches to containers for a service.
docker-compose up

# Stops containers and removes containers, networks, volumes, and images created by up.
docker-compose down
```

## Config file reference

### Building

```yml
web:
  # build from Dockerfile
  build: .
  # build from custom Dockerfile
  build:
    context: ./dir
    dockerfile: Dockerfile.dev
  # build from image
  image: ubuntu
  image: ubuntu:14.04
  image: tutum/influxdb
  image: example-registry:4000/postgresql
  image: a4bc65fd
```

### Ports

```yml
ports:
  - "3000"
  - "8000:80"  # guest:host
# expose ports to linked services (not to host)
expose: ["3000"]
```

### Commands

```yml
# command to execute
command: bundle exec thin -p 3000
command: [bundle, exec, thin, -p, 3000]

# override the entrypoint
entrypoint: /app/start.sh
entrypoint: [php, -d, vendor/bin/phpunit]
```

### Environment variables

```yml
# environment vars
environment:
  RACK_ENV: development
environment:
  - RACK_ENV=development

# environment vars from file
env_file: .env
env_file: [.env, .development.env]
```

### Dependencies

```yml
# makes the `db` service available as the hostname `database`
# (implies depends_on)
links:
  - db:database
  - redis

# make sure `db` is alive before starting
depends_on:
  - db
```

### Other options

```yml
# make this service extend another
extends:
  file: common.yml  # optional
  service: webapp
volumes:
  - /var/lib/mysql
  - ./_data:/var/lib/mysql
```

## Advanced features

### Labels

```yml
services:
  web:
    labels:
      com.example.description: "Accounting web app"
```

### DNS servers

```yml
services:
  web:
    dns: 8.8.8.8
    dns:
      - 8.8.8.8
      - 8.8.4.4
```

### Devices

```yml
services:
  web:
    devices:
      - "/dev/ttyUSB0:/dev/ttyUSB0"
```

### External links

```yml
services:
  web:
    external_links:
      - redis_1
      - project_db_1:mysql
```

### Hosts

```yml
services:
  web:
    extra_hosts:
      - "somehost:192.168.1.100"
```

### Network

```yml
# creates a custom network called `frontend`
networks:
  frontend:
```

### External network

```yml
# join a preexisting network
networks:
  default:
    external:
      name: frontend
```

## References

Based off cheatsheet from <https://devhints.io/docker-compose>.