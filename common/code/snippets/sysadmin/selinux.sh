# Searching for records and creating a checkpoint, to ensure that audit records that have already been seen don't show up again on the next search
ausearch --checkpoint="./audit-checkpoint" -m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR -i -ts today

# Searching for records based on the processes comm name, this is the executable name from the task in the kernel
ausearch -c "httpd" -m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR -i

# Finding events where an admin (or program) changed the enforcing state of SELinux
ausearch -m MAC_STATUS -i

# Set security context type
chcon -Rv --type=httpd_sys_content_t /var/www/html/_
chcon --reference /var/www/html/ /var/www/html/_
semanage fcontext -a -t httpd_sys_content_t "/html(/.*)?"
semanage fcontext -a -e /var/www/ /foo/
restorecon -Rv /var/www/html

# Relabel Complete Filesystem
genhomedircon
touch /.autorelabel
reboot 

# Allowing Access to a Port
semanage port -a -t http_port_t -p tcp 81

# Using Analysis Tools
sesearch -ACR -s httpd_t -t "httpd.*" -c file -p write

# Make a Type Enforcement policy file
grep smtpd_t /var/log/audit/audit.log | audit2allow -m postgreylocal > postgreylocal.te
audit2allow --dmesg -m postgreylocal

# Load policy module into the current SELinux policy
semodule -i postgreylocal.pp

# List/Check if type and aliases exist
seinfo -x -tTYPE

# Generate policy file templates
sepolgen --application /usr/bin/_
