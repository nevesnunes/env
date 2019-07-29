@Test
public void stringCaching() throws Exception {
    String urlStr = "http://my_server_url/path/to/wsdl&=";
    Random rand = new Random();
    while (true) {
        URL url = new URL(urlStr + rand.nextInt());
        Service.create(url, new QName("http://schemas.microsoft.com/sharepoint/soap/", "Lists"));
    }
}

@Test
public void manyClientsUniqueWsdlSingleCall() throws Exception {
    URL wurl = getClass().getResource("/wsdl/hello_world.wsdl");
    byte wsdl[] = IOUtils.readBytesFromStream(wurl.openStream());
    final int max = 10000;

    List<URL> urls = new ArrayList<URL>(max);
    for (int x = 0; x < max; x++) {
        File f = FileUtils.createTempFile("memtest", ".wsdl", FileUtils.createTmpDir(), true);
        FileOutputStream fout = new FileOutputStream(f);
        fout.write(wsdl);
        fout.close();
        urls.add(f.toURI().toURL());
    }
    int count = 0;
    for (URL url : urls) {
        count++;
        if (count == 500) {
            count = 0;
            System.gc();
            long used = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
            System.out.println("Total used: " + used);
        }
        org.apache.hello_world_soap_http.SOAPService service
            = new org.apache.hello_world_soap_http.SOAPService(url);
        Greeter greeter = service.getSoapPort();
        String response = new String("Bonjour");
        ((BindingProvider)greeter).getRequestContext()
        .put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
             "http://localhost:" + PORT + "/SoapContext/SoapPort");
        greeter.greetMe("test");
        String reply = greeter.sayHi();
        assertNotNull("no response received from service", reply);
        assertEquals(response, reply);
    }
}
