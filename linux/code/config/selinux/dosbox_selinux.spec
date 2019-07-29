# vim: sw=4:ts=4:et


%define relabel_files() \
restorecon -R /usr/bin/dosbox; \

%define selinux_policyver 0.0.0

Name:   dosbox_selinux
Version:	1.0
Release:	1%{?dist}
Summary:	SELinux policy module for dosbox

Group:	System Environment/Base		
License:	GPLv2+	
# This is an example. You will need to change it.
URL:		http://HOSTNAME
Source0:	dosbox.pp
Source1:	dosbox.if
Source2:	dosbox_selinux.8


Requires: policycoreutils, libselinux-utils
Requires(post): selinux-policy-base >= %{selinux_policyver}, policycoreutils
Requires(postun): policycoreutils
BuildArch: noarch

%description
This package installs and sets up the  SELinux policy security module for dosbox.

%install
install -d %{buildroot}%{_datadir}/selinux/packages
install -m 644 %{SOURCE0} %{buildroot}%{_datadir}/selinux/packages
install -d %{buildroot}%{_datadir}/selinux/devel/include/contrib
install -m 644 %{SOURCE1} %{buildroot}%{_datadir}/selinux/devel/include/contrib/
install -d %{buildroot}%{_mandir}/man8/
install -m 644 %{SOURCE2} %{buildroot}%{_mandir}/man8/dosbox_selinux.8
install -d %{buildroot}/etc/selinux/targeted/contexts/users/


%post
semodule -n -i %{_datadir}/selinux/packages/dosbox.pp
if /usr/sbin/selinuxenabled ; then
    /usr/sbin/load_policy
    %relabel_files

fi;
exit 0

%postun
if [ $1 -eq 0 ]; then
    semodule -n -r dosbox
    if /usr/sbin/selinuxenabled ; then
       /usr/sbin/load_policy
       %relabel_files

    fi;
fi;
exit 0

%files
%attr(0600,root,root) %{_datadir}/selinux/packages/dosbox.pp
%{_datadir}/selinux/devel/include/contrib/dosbox.if
%{_mandir}/man8/dosbox_selinux.8.*


%changelog
* Sat Jan 13 2018 YOUR NAME <YOUR@EMAILADDRESS> 1.0-1
- Initial version

