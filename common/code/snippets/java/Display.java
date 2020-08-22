throw new java.lang.RuntimeException("size = " + buf.length);
throw new java.lang.RuntimeException("BOOM");
throw new org.springframework.web.client.RestClientException("BOOM");

this.restTemplate.getRequestFactory();

List<java.lang.reflect.Field> fields = new ArrayList<>();
for (java.lang.reflect.Field f : SpringApplication.class.getDeclaredFields()) {
	if (f.getName().toLowerCase().contains("context")) {
		fields.add(f);
	}
}

String newLine = System.getProperty("line.separator");
StringBuilder result = new StringBuilder();
for (java.lang.reflect.Field f : this.getClass().getDeclaredFields()) {
    result.append("  ");
    f.setAccessible(true);
    result.append(f.getName());
    result.append(": ");
    result.append(f.get(this));
    result.append(newLine);
}
return result;

com.fasterxml.jackson.databind.ObjectMapper jsonObjectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
return jsonObjectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(doc);

new java.sql.Date(object.getAttribute(FOO_DATE_KEY, Long.class))
new Date(new Long("-2303596800000"))
new Date(new Long("-3600000"))
obj instanceof Long

pathElements = new ArrayList(pathElements);
pathElements.subList(0, pos)
List<String> l = new ArrayList<>();
l.add("foo");

System.getProperties()
System.getProperty("javax.net.ssl.trustStore")
System.setProperty("javax.net.ssl.trustStore", null)

((HttpServletRequest)request).getRequestURL() + "?" + ((HttpServletRequest)request).getQueryString()

path.replaceAll(oldName + "/*$", newName)

new java.io.FileInputStream("/C:/foo/apache-tomcat-7.0.67-windows-x64/wtpwebapps/fooWeb/WEB-INF/lib/bar-0.0.1-SNAPSHOT.jar/app/data/baz.json")
RequestData.class.getResource("/app/data/baz.json")
RequestData.class.getResourceAsStream("/app/data/baz.json")

final int bufferSize = 1024;
final char[] buffer = new char[bufferSize];
final java.lang.StringBuilder out = new java.lang.StringBuilder();
java.io.Reader in = new java.io.InputStreamReader(response.getBody(), "UTF-8");
for (;;) {
    int rsz = in.read(buffer, 0, buffer.length);
    if (rsz < 0)
        break;
    out.append(buffer, 0, rsz);
}
return out.toString();

int len;
int size = 1024;
java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
byte[] buf = new byte[size];
while ((len = stream.read(buf, 0, size)) != -1)
	bos.write(buf, 0, len);
buf = bos.toByteArray();

java.io.FileOutputStream fos = new java.io.FileOutputStream("C:\\foo\\a.jpg");
fos.write(buf);

restTemplate.exchange(new URI("https://localhost/foo/rest/documents/"), HttpMethod.GET, request, Document.class);

String s = ""; for (Foo f : foos) s += f.getName() + "\n"; return s;

new String(bytes)

java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
soapMessage.writeTo(out);
(new String(out.toByteArray())).toString();

json = json.replaceAll("\"", "\\\\\"")

Thread.currentThread().getContextClassLoader().getResource("/");
Foo.class.getResource("/");

invocation.getArguments()[1] instanceof java.util.LinkedList
Thread.currentThread().getContextClassLoader().getResource("app/config/foo.csv");

httpServletRequest.getScheme()
httpServletRequest.getLocalName()
httpServletRequest.getContextPath()
httpServletRequest.getServletPath()
httpServletRequest.getRequestURL()

System.getProperty("file.encoding")
java.nio.charset.Charset.defaultCharset()
(new java.io.OutputStreamWriter(new java.io.ByteArrayOutputStream())).getEncoding()

new String(result.getResults().get(4).getNameForLanguage("en").getBytes(
		java.nio.charset.StandardCharsets.UTF_8.toString()),
		java.nio.charset.StandardCharsets.ISO_8859_1.toString())
new String(result.getResults().get(4).getNameForLanguage("en").getBytes(
		java.nio.charset.StandardCharsets.ISO_8859_1.toString()),
		java.nio.charset.StandardCharsets.UTF_8.toString())
new String(xml.getBytes(
		java.nio.charset.StandardCharsets.UTF_8.toString()))
new String(xml.getBytes(
		java.nio.charset.StandardCharsets.ISO_8859_1.toString()))

org.springframework.context.annotation.AnnotationConfigApplicationContext ctx = new org.springframework.context.annotation.AnnotationConfigApplicationContext();
ctx.register(com.foo.Bar.class);
ctx.refresh();
ctx.getEnvironment().getProperty("foo");

(new File(xslPath)).getParentFile().getParentFile().toURI().toURL()
