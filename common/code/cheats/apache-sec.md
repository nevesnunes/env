# +

https://wiki.debian.org/Apache/Hardening
https://www.cyberciti.biz/tips/php-security-best-practices-tutorial.html

apache2ctl configtest

/etc/apache2/apache2.conf
/etc/apache/httpd.conf

# Apache HTTP Server Bypass Access Restriction Vulnerability via Require Directive

# Apache HTTP Server Request Smuggling Vulnerability via Invalid Chunk-Extension Characters

# HTTP TRACE/TRACK Methods Enabled
TraceEnable Off

https://www.owasp.org/index.php/Cross_Site_Tracing

# HTTPoxy Vulnerability
RequestHeader unset Proxy early

https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-httpoxy-vulnerability

# Indexable Web Directories
before the <Directory> blocks:
Options -Indexes

Now, find the <Directory /var/www/html> block and change the Options statement within to:

Options -Indexes +FollowSymLinks

Make sure you also adjust the AllowOverride directive in the same block from ‘None’ to:

AllowOverride All

# No X-FRAME-OPTIONS Header
Header always append X-Frame-Options SAMEORIGIN

There are three settings for X-Frame-Options:

    SAMEORIGIN: This setting will allow page to be displayed in frame on the same origin as the page itself.
    DENY: This setting will prevent a page displaying in a frame or iframe.
    ALLOW-FROM uri: This setting will allow page to be displayed only on the specified origin.

# Discovered HTTP Methods

# Discovered Web Directories

# Server version and OS
ServerTokens Prod
ServerSignature Off

# Limit HTTP Methods to GET, HEAD, POST
<Location />
<LimitExcept GET HEAD POST>
Require all denied
</LimitExcept>
</Location>

# Basic XSS Prevention
Header set X-XSS-Protection "1; mode=block"
