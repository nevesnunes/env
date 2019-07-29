# +

```bash
mvn help:effective-pom

mvn validate
mvn dependency:analyze -Dverbose -DignoreNonCompile
mvn compile dependency:tree -Dverbose -Dincludes=org.springframework.\* -am --offline
mvn org.apache.maven.plugins:maven-dependency-plugin:3.1.1:display-ancestors

mvn dependency:sources dependency:resolve -Dclassifier=javadoc --fail-at-end

mvn help:describe -Dcmd=org.jacoco:jacoco-maven-plugin:prepare-agent -am
mvn fr.jcgay.maven.plugins:buildplan-maven-plugin:list -am

mvn -DgroupId=commons-io -DartifactId=commons-io -Dversion=1.4 dependency:get

mvn package -DskipTests
mvn package -Dmaven.test.skip.exec=true
mvn test -am --offline -DfailIfNoTests=false -Dtest=FooClass#fooMethod

mvn clean package -pl fooEar -am
```

# Copy dependencies
# http://maven.apache.org/plugins/maven-dependency-plugin/copy-dependencies-mojo.html

```bash
mvn dependency:copy-dependencies \
    -DoutputDirectory=/foo \
    -DincludeGroupIds=org.slf4j
```

# Download dependencies

```bash
mvn clean initialize
```

# Local install

```bash
mvn install:install-file \
   -Dfile=/c/foo-2.7.2.jar \
   -DpomFile=/c/foo-2.7.2.pom \
   -DgroupId=com.abc.def \
   -DartifactId=foo \
   -Dversion=2.6.999 \
   -Dpackaging=jar \
   -DgeneratePom=true
```

# Remote Deploy

```bash
mvn deploy:deploy-file \
   -Dfile=workspace/foo/fooCommon/target/fooCommon-0.0.1-SNAPSHOT.jar \
   -DgroupId=com.abc \
   -DartifactId=fooCommon \
   -Dversion=0.0.1-SNAPSHOT \
   -Dpackaging=jar \
   -DgeneratePom=true \
   -Durl="http://nexus.foo.com/nexus/repository/public/" \
   -DrepositoryId="nexus-public-group"
```

```settings.xml
<server>
    <id>nexus-public-group</id>
    <username>foo</username>
    <password>foo</password>
</server>
```

# Nexus latest snapshot

http://%%%/nexus/repository/public/com/%%%/0.0.1-SNAPSHOT/maven-metadata.xml

# Debug, Verbose

mvn -X

# SSL

https://maven.apache.org/guides/mini/guide-encryption.html
https://stackoverflow.com/questions/30769636/how-does-maven-3-password-encryption-work/43118084#43118084

https://maven.apache.org/guides/mini/guide-repository-ssl.html
https://stackoverflow.com/a/25912982

mvn validate -Djavax.net.debug=ssl
mvn clean install -U -Djavax.net.debug=ssl 2>&1 | vim -
\(err\|fail\|fatal\|warn\|alert\|invalid\)

%% Invalidated:  [Session-3, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
main, SEND TLSv1.2 ALERT:  fatal, description = certificate_unknown
main, WRITE: TLSv1.2 Alert, length = 2
main, called closeSocket()
main, handling exception: javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target

https://www.sslshopper.com/article-most-common-java-keytool-keystore-commands.html
https://gist.github.com/Jakuje/5a993d2b2d8a9cac35203599e49e6831
https://medium.freecodecamp.org/openssl-command-cheatsheet-b441be1e8c4a

```bash
# Expect: echo "$JAVA_HOME" | grep -i jdk
keytool -import -trustcacerts -alias fooApp -file ~/opt/certificates/fooApp.cer -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass changeit -noprompt
keytool -list -v -keystore "$JAVA_HOME/jre/lib/security/cacerts" | grep -i foo
```

### dump certificates

```bash
keytool -list -v -keystore foo.jks

certutil -dump foo.p12
openssl pkcs12 -in foo.p12 -info -noout
openssl req -in server.csr -text -noout
openssl x509 -in server.crt -text -noout
```

### localhost

```bash
openssl req -x509 -out localhost.crt -keyout localhost.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
```

### Objects

.mavenrc
server.xml
