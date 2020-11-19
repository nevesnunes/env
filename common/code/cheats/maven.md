# +

```bash
mvn help:effective-pom

# Check if build can be run successfully (e.g. scm: repository URL; enforcer: environmental constraints such as Maven version, JDK version and OS family)
#
# Plugins under maven-sources/maven:
# - ./plugins/tools/enforcer/maven-enforcer-plugin/src/main/java/org/apache/maven/plugins/enforcer/EnforceMojo.java:53:@Mojo( name = "enforce", defaultPhase = LifecyclePhase.VALIDATE, requiresDependencyCollection = ResolutionScope.TEST, threadSafe = true )
# - ./plugins/tools/maven-dependency-plugin/src/main/java/org/apache/maven/plugins/dependency/DisplayAncestorsMojo.java:42:@Mojo( name = "display-ancestors", threadSafe = true, requiresProject = true, defaultPhase = LifecyclePhase.VALIDATE )
# - ./plugins/tools/scm/maven-scm-plugin/src/main/java/org/apache/maven/scm/plugin/ValidateMojo.java:40:@Execute( phase = LifecyclePhase.VALIDATE )
mvn validate
# Linting: check used undeclared and unused declared dependencies
mvn dependency:analyze -Dverbose -DignoreNonCompile
# List if dependencies were omitted due to other references
mvn compile dependency:tree -Dincludes=org.springframework.\* -DoutputFile=/tmp/1 -am --offline
# https://maven.apache.org/plugins/maven-dependency-plugin/examples/resolving-conflicts-using-the-dependency-tree.html
mvn org.apache.maven.plugins:maven-dependency-plugin:2.10:tree -Dverbose=true
# List parent POMs of project
mvn org.apache.maven.plugins:maven-dependency-plugin:3.1.1:display-ancestors
# ||
mvn com.github.exampledriven:hierarchy-maven-plugin:1.7-SNAPSHOT:tree -Dlevel=full
# https://stackoverflow.com/questions/40599913/how-does-plugin-validation-work-in-maven-and-why-does-it-build-my-project-with

mvn dependency:sources dependency:resolve -Dclassifier=javadoc --fail-at-end
mvn javadoc:javadoc
# http://maven.apache.org/plugins/maven-javadoc-plugin/

mvn clean eclipse:eclipse
# https://stackoverflow.com/questions/6174550/eclipse-java-debugging-source-not-found

mvn help:describe -Dcmd=org.jacoco:jacoco-maven-plugin:prepare-agent -am
mvn fr.jcgay.maven.plugins:buildplan-maven-plugin:list -am

mvn \
    -DgroupId=commons-io \
    -DartifactId=commons-io \
    -Dversion=1.4 \
    dependency:get 
# ||
mvn \
    -DremoteRepositories=central::default::https://repo.maven.apache.org/maven2 \
    -Dartifact=groupId:artifactId:version \
    dependency:get 
# ||
mvn \
    -DremoteRepositories=central::default::http://repository.sl.pt/nexus/content/repositories/public \
    -Dartifact=groupId:artifactId:version \
    dependency:get 

mvn package -DskipTests
mvn package -Dmaven.test.skip.exec=true
mvn test -am --offline -DfailIfNoTests=false -Dtest=FooClass#fooMethod

mvn clean package -pl fooEar -am
```

# Copy dependencies

```bash
mvn dependency:copy-dependencies \
    -DoutputDirectory=/foo \
    -DincludeGroupIds=org.slf4j
```

- http://maven.apache.org/plugins/maven-dependency-plugin/copy-dependencies-mojo.html

# Download dependencies

```bash
mvn clean initialize
```

# Local install

```bash
mvn org.apache.maven.plugins:maven-source-plugin:3.0.1:jar
mvn install:install-file \
   -Dfile=/c/foo-2.7.2.jar \
   -Dsources=/c/foo-2.7.2-sources.jar \
   -DpomFile=/c/foo-2.7.2.pom \
   -DgroupId=com.abc.def \
   -DartifactId=foo \
   -Dversion=2.6.999 \
   -Dpackaging=jar \
   -DgeneratePom=true

mvn install:install-file \
   -Dfile=/c/foo-2.7.2.pom \
   -DpomFile=/c/foo-2.7.2.pom \
   -DgroupId=com.abc.def \
   -DartifactId=foo \
   -Dversion=2.6.999 \
   -Dpackaging=pom \
   -DgeneratePom=true
```

- Issue: dependency snapshot is missing from repository, but it is referenced in external dependency
    - Workaround: install dependency from local repository as snapshot version, need to add suffix `-SNAPSHOT` to generated pom, under: version, properties/jackson.version...

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

settings.xml:

```xml
<server>
    <id>nexus-public-group</id>
    <username>foo</username>
    <password>foo</password>
</server>
```

# Nexus latest snapshot

http://%%%/nexus/repository/public/com/%%%/0.0.1-SNAPSHOT/maven-metadata.xml

# Debug, Verbose

```bash
mvn -X
```

# SSL

- https://maven.apache.org/guides/mini/guide-encryption.html
    - [security \- How does Maven 3 password encryption work? \- Stack Overflow](https://stackoverflow.com/questions/30769636/how-does-maven-3-password-encryption-work/43118084#43118084)
- https://maven.apache.org/guides/mini/guide-repository-ssl.html
    - [java \- Problems using Maven and SSL behind proxy \- Stack Overflow](https://stackoverflow.com/a/25912982)

```bash
mvn validate -Djavax.net.debug=ssl
# After: rm *.repositories *.sha1 on dependency's local repository directory
mvn clean install -U -Djavax.net.debug=ssl 2>&1 | vim -
# \(err\|fail\|fatal\|warn\|alert\|invalid\)
```

> %% Invalidated:  [Session-3, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
> main, SEND TLSv1.2 ALERT:  fatal, description = certificate_unknown
> main, WRITE: TLSv1.2 Alert, length = 2
> main, called closeSocket()
> main, handling exception: javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target

- https://www.sslshopper.com/article-most-common-java-keytool-keystore-commands.html
- https://gist.github.com/Jakuje/5a993d2b2d8a9cac35203599e49e6831
- https://medium.freecodecamp.org/openssl-command-cheatsheet-b441be1e8c4a

```bash
# Expect: echo "$JAVA_HOME" | grep -i jdk
keytool -import -trustcacerts -alias fooApp -file ~/opt/certificates/fooApp.cer -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass changeit -noprompt

keytool -list -v -keystore "$JAVA_HOME/jre/lib/security/cacerts" -storepass changeit -noprompt | grep -i foo
keytool -list -v -keystore withoutPassword.jks -protected | grep -i foo

keytool -list -v -keystore certificates.jks -protected 2>&1 | \
    gawk 'match($0, /(Alias name: )(.*)/, e) {print e[2]}' | \
    env LC_ALL=C sed 's/[^a-zA-Z0-9,._+@%/-]/\\&/g' | \
    xargs -i sh -c 'keytool -exportcert -keystore certificates.jks -protected -alias "$1" -file "$(printf '%q' "$1")".crt' _ {}

target_keystore=
keytool -list -v -keystore certificates.jks -protected 2>&1 | \
    gawk 'match($0, /(Alias name: )(.*)/, e) {print e[2]}' | \
    env LC_ALL=C sed 's/[^a-zA-Z0-9,._+@%/-]/\\&/g' | \
    xargs -i sh -c 'keytool -import -trustcacerts -alias "$1" -file "$(printf '%q' "$1")".crt -keystore "'"$target_keystore"'" -storepass changeit -noprompt' _ {}

~/opt/jks-certificate-expiry-checker.sh

# import private key and certificate
cat /etc/ssl/cert.pem my-ca-file.crt > ca-certs.pem
openssl pkcs12 -export -in my.crt -inkey my.key -chain -CAfile ca-certs.pem -name "my-domain.com" -out my.p12
keytool -importkeystore -deststorepass MY-KEYSTORE-PASS -destkeystore my-keystore.jks -srckeystore my.p12 -srcstoretype PKCS12
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

- .mavenrc
- server.xml

# java/jdk/jre version

https://maven.apache.org/plugins/maven-compiler-plugin/examples/compile-using-different-jdk.html

# validating command line properties

```bash
mvn foo -Dbar=true -X
```

1. On unset property exception, check available parameters of first class in stack trace
    - https://github.com/apache/maven-assembly-plugin/blob/master/src/main/java/org/apache/maven/plugins/assembly/mojos/AbstractAssemblyMojo.java
2. `@Parameter` annotated attributes must set `property` key to be parsed from command line
    - https://jar-download.com/artifacts/org.apache.maven.plugin-tools/maven-plugin-annotations/3.6.0/source-code/org/apache/maven/plugins/annotations/Parameter.java
