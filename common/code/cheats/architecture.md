# Methodology

- [The Twelve\-Factor App ](https://12factor.net/)
- [Rationale and implications of the zero \(0\) complexity principles &\#8212; 0Complexity Design Principles](https://nocomplexity.com/documents/0complexity/rationaleof0cxprinciples.html)

# Scalability

- pageviews per minute
    - upper bounds - most visited sites - e.g. wikipedia
- database server in separate host

# RESTful API

- Client-server model — a client requests data from a separated server, often over a network
- Uniform interface — all clients and servers interact with the API in the same way (e.g., multiple resource endpoints)
- Layered system — a client doesn't have to be connected to the end server
- Statelessness — a client holds the state between requests and responses
- Cacheability — a client can cache a server's reponse

### Idempotency

- Uber Eats glitch: retried request returns unknown state, should raise an alert, neither success nor failure
    - if treated as success, then clients have free orders
    - if treated as failure but payment went through, then clients repeating orders would be overcharged
    - https://twitter.com/GergelyOrosz/status/1502947315279187979

# Configuration

### Overriding

1. Run-control files under /etc (or at fixed location elsewhere in systemland): What will most users on this system want most of the time? What will this particular user want most of the time?
2. System-set environment variables: How should this session (i.e., a potentially large series of related executions) be tailored?
3. Run-control files (or ‘dotfiles’) in the user's home directory.
4. User-set environment variables.
5. Switches and arguments passed to the program on the command line that invoked it: What is most useful for this particular run?

- [Where Configurations Live](http://www.catb.org/~esr/writings/taoup/html/ch10s02.html)

### Substitution

- `envsubst`: replace variables in stream
    - [Dynamic configuration variables in Prometheus Config · Issue \#6047 · prometheus/prometheus · GitHub](https://github.com/prometheus/prometheus/issues/6047)

# Naming

- [NetworkInterfaceNames \- Debian Wiki](https://wiki.debian.org/NetworkInterfaceNames)

# Privileges

- unix-domain sockets: SCM_CREDENTIALS, SO_PEERCRED
- pkexec
    > The thing with setuid/setgid is that the invoked privileged process inherits a lot of implicit state and context that people aren't really aware of or fully understand. i.e. it's not just env vars and argv[], it's cgroup memberships, audit fields, security contexts, open fds, child pids, parent pids, cpu masks, IO/CPU scheduling priorities, various prctl() settings, tty control, signal masks + handlers, … and so on. And it's not even clear what gets inherited as many of these process properties are added all the time.
    > If you do privileged execution of specific operations via IPC you get the guarantee that whatever is done, is done from a well-defined, pristine execution environment, without leaking context implicitly. The IPC message is the *full* vulnerable surface, and that's as minimal as it can get. And that's great. 
    - [Fedora and pkexec \(LWN\.net\)](https://lwn.net/SubscriberLink/883547/d2b752eb979b3eb1/)

# Hot-Swapping

### Executables

- reuse sockets
    - systemd socket activation + delegation
    - [GitHub \- zimbatm/socketmaster: Zero downtime restarts for your apps](https://github.com/zimbatm/socketmaster)
- pid reparenting
    - [Controlling nginx \- Upgrading Executable on the Fly](https://nginx.org/en/docs/control.html#upgrade)
    - [caddy/upgrade\.go at v1 · caddyserver/caddy · GitHub](https://github.com/caddyserver/caddy/blob/v1/upgrade.go)
