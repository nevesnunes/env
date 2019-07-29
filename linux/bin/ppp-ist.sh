#!/usr/bin/env bash

# Listen with:
#sudo tcpdump -vv -i wlp0s29f7u2 &>gres

/usr/libexec/nm-pptp-service &
/sbin/modprobe nf_conntrack_pptp &
/sbin/pppd pty '/sbin/pptp 193.136.132.10 --nolaunchpppd --loglevel 2 --logstring nm-pptp-service-script ipparam nm-pptp-service-script' debug dump logfd 2 nodetach lock usepeerdns noipdefault nodefaultroute noauth refuse-eap refuse-pap refuse-chap require-mppe-128 lcp-echo-failure 5 lcp-echo-interval 30 plugin /usr/lib64/pppd/2.4.7/nm-pptp-pppd-plugin.so
