# Manual war deploy

```bash
tomcat_dir=/c/foo/apache-tomcat-7.0.67-windows-x64
rm -r "$tomcat_dir"/webapps/foo*
rm -r "$tomcat_dir"/work/Catalina/localhost/foo*
```

# Webapp deploy configuration

- ! should match deployed app entries
- ! host tag should have only one context tag for a given app

/c/foo/eclipse-workspace/Servers/Tomcat v7.0 Server at localhost-config/server.xml
```xml
<Host>
    [...]
    <Context docBase="fooWeb" path="/foo" reloadable="true" source="org.eclipse.jst.jee.server:fooWeb"/>
</Host>
```
=> C:\foo\apache-tomcat-7.0.67-windows-x64\wtpwebapps\fooWeb

# Endpoints

```bash
curl -v -u admin:pass localhost:8080/manager/html/list
curl -v -u admin:pass localhost:8080/manager/text/list
```

# Generate web service address with https

```xml
<Connector port="8080" protocol="HTTP/1.1"
        connectionTimeout="20000" scheme="https" proxyPort="443"
        redirectPort="8443" maxHttpHeaderSize="65536" />
```

- vs. valve forwarded for header
    - remoteIpHeader, protocolHeader
    - https://tomcat.apache.org/tomcat-8.5-doc/config/valve.html

- https://tomcat.apache.org/tomcat-8.5-doc/config/http.html

# Servlet, controller encoding

```xml
<Connector URIEncoding="UTF-8" />
```
