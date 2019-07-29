try (InputStream in = new FileInputStream(imageFile)) {
    PDDocument embeddableDocument = PDDocument.load(in, "");
    if (embeddableDocument.isEncrypted()) {
        embeddableDocument.setAllSecurityToBeRemoved(true);
    }
    if (embeddableDocument.getNumberOfPages() < 1) {
        log.warn("embeddableDocument has no pages.");
    } else {
        PDPage embeddablePage = embeddableDocument.getPage(0);
        PDFormXObject xObject = importAsXObject(embeddableDocument, embeddablePage);
        
        // Resize xObject to fit free space while preserving ratios				
        float pageFreeWidth = tableWidth;
        float pageFreeHeight = yStart;
        float pageFreeRatio = pageFreeWidth / pageFreeHeight;
        
        Matrix matrix = xObject.getMatrix();
        float xObjectWidth = xObject.getBBox().getWidth();
        float xObjectHeight = xObject.getBBox().getHeight();
        float xObjectRatio = xObjectWidth / xObjectHeight;
        
        float xObjectNewWidth = (pageFreeRatio > xObjectRatio)
                ? (xObjectWidth * pageFreeHeight / xObjectHeight)
                : (pageFreeWidth);
        float xObjectNewHeight = (pageFreeRatio > xObjectRatio)
                ? (pageFreeHeight)
                : (xObjectHeight * pageFreeWidth / xObjectWidth);

        // xObject matrix:
        // [
        //		column 0: ["scaleX", "shearX", "translateX"], 
        //		column 1: ["shearY", "scaleY", "translateY"]
        // ]
        matrix.setValue(0, 0, xObjectNewWidth / xObjectWidth);
        matrix.setValue(1, 1, xObjectNewHeight / xObjectHeight);
        matrix.setValue(2, 0, margin);
        matrix.setValue(2, 1, yStart - xObjectNewHeight - margin);
        xObject.setMatrix(matrix.createAffineTransform());

        // Add resized xObject
        page.getResources().add(xObject, "X");

        // Draw resized xObject
        try (PDPageContentStream content = new PDPageContentStream(document, page,
                PDPageContentStream.AppendMode.APPEND, false)) {
            content.drawForm(xObject);
        }
    }
}
