# Manual war deploy

```
tomcat_dir=/d/apache-tomcat-7.0.67-windows-x64
rm -r "$tomcat_dir"/webapps/motion-*
rm -r "$tomcat_dir"/work/Catalina/localhost/motion-*
```

# Endpoints

curl -v -u admin:pass localhost:8080/manager/html/list
curl -v -u admin:pass localhost:8080/manager/text/list

# Generate web service address with https

<Connector port="8080" protocol="HTTP/1.1"
        connectionTimeout="20000" scheme="https" proxyPort="443"
        redirectPort="8443" maxHttpHeaderSize="65536" />

# Servlet, controller encoding

<Connector URIEncoding="UTF-8" />
