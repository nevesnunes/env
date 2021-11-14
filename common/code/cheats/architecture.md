# Methodology

- [The Twelve\-Factor App ](https://12factor.net/)
- [Rationale and implications of the zero \(0\) complexity principles &\#8212; 0Complexity Design Principles](https://nocomplexity.com/documents/0complexity/rationaleof0cxprinciples.html)

# Scalability

- pageviews per minute
    - upper bounds - most visited sites - e.g. wikipedia
- database server in separate host

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

# Design decisions

- [NetworkInterfaceNames \- Debian Wiki](https://wiki.debian.org/NetworkInterfaceNames)
