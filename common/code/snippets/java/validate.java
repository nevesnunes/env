DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setNamespaceAware(true);
dbf.setValidating(true);
DocumentBuilder builder = dbf.newDocumentBuilder();
Document doc = builder.parse("src/main/resources/app/signatures/1.sig");
Node nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
DOMResult result = new DOMResult();

// Extend elements with xsd types
try {
    final String xsdPath = "src/main/resources/app/xsd/eni/xmldsig-core-schema.xsd";
    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    Schema schema = factory.newSchema(new File(xsdPath));
    Validator validator = schema.newValidator();
    validator.validate(new DOMSource(doc.getDocumentElement()), result);
} catch (Exception e) {
    throw new AssertionError(e);
}

//DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), result.getNode());
DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl);
XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
XMLSignature signature = factory.unmarshalXMLSignature(valContext);
