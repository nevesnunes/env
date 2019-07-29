Manually copy the content of the XSD into the types section of the WSDL and replace the schema import there

# Maven

<plugin>
  <groupId>org.jvnet.jax-ws-commons</groupId>
  <artifactId>jaxws-maven-plugin</artifactId>
  <version>2.2</version>
  <executions>
    <execution>
      <id>SomeId</id>
      <goals>
        <goal>wsgen</goal>
      </goals>
      <phase>prepare-package</phase>
      <configuration>
        <sei>some.class.Name</sei>
        <genWsdl>true</genWsdl>
        <keep>true</keep>
        <resourceDestDir>some/target/dir</resourceDestDir>
        <inlineSchemas>true</inlineSchemas>
      </configuration>
    </execution>
  </executions>
</plugin>
