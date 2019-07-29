// The xsi namespace is already present in the envelope.
// For conformance with the old web service interface,
// we need to remove the namespace from the children.
for (Node node : NamedNodeMapIterable.of(child.getAttributes())) {
    logger.debug(String.format("SOAP Handler: attribute: %s = %s", node.getNodeName(),
            node.getNodeValue()));
    if (node.getNodeName().equals(LoginResponseElements.getXmlnsXsiKey())) {
        ((Element) child).removeAttribute(LoginResponseElements.getXmlnsXsiKey());
    }
}
