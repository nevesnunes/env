Elasticsearch, Kafka, MongoDB
Apps, DBs, CI/CD, monitoring

# Install

Install the software binaries and all dependencies.

- Bash, Chef, Ansible, Puppet

# Configure

Configure the software at runtime: e.g., configure port settings, file paths, users, leaders, followers, replication, etc.

- Bash, Chef, Ansible, Puppet

# Provision

Provision the infrastructure: e.g., E02 Instances, load balancers, network topology, security groups, IAM permissions, etc.

- Terraform, CloudFormation

# Deploy

Deploy the service on top of the infrastructure. Roll out updates with no downtime: e.g., blue-green, rolling, canary deployments.

- Scripts, Orchestration tools (ECS, K88, Nomad)

# Security

Encryption in transit (TLS) and on disk, authentication, authorization, secrets management, server hardening.

- ACM, EBS Volumes, Cognito, Vault, CiS

# Monitoring

Availability metrics, business metrics, app metrics, server, metrics, events, observability, tracing, alerting.

- CloudWatch, DataDog, New Relic, Honeycomb

# Logs

Rotate logs on disk. Aggregate log data to a central location.

- CIoudWatch Logs, ELK, Sumo Logic, Papertrail

# Backup and restore

Make backups of DBs, caches, and other data on a scheduled basis. Replicate to separate region/account.

- RDS, ElastiCache, ec2-snapper, Lambda

# Networking

VPCs, subnets, static and dynamic lPs, service discovery, service mesh, firewalls, DNS, SSH access, VPN access.

- EIPs, ENIs, VPCs, NACLs, 865, Route 53, OpenVPN

# High availability

Withstand outages of individual processes, EC2 Instances, services, Availability Zones, and regions.

- Multi AZ, multi-region, replication, ASGs, ELBs

# Scalability

Scale up and down in response to load. Scale horizontally (more servers) and/or vertically (bigger servers).

# Performance

Optimize CPU, memory, disk, network, GPU and usage. Query tuning. Benchmarking, load testing, profiling.

- Dynatrace, valgrind, VisualVM, ab, Jmeter

# Cost optimization

Pick proper instance types, use spot and reserved instances, use auto scaling, nuke unused resources

- ASGs, replication, sharding, caching, divide and conquer

# Documentation

Document your code, architecture, and practices. Create playbooks to respond to incidents.

- READMEs, wikis, Slack

# Tests

Write automated tests for your infrastructure code. Run tests after every commit and nightly.

- Terratest

# Maintenance

Update the software. Update tools (e.g., Terraform, Packer). Update to latest best practices.
Add new features. Fix bugs. Install security patches.

- Human beings, Gruntwork commercial support.
