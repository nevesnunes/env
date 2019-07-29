<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
  version="1.0"
  >
  <xsl:output method="html"/> 
 
  <xsl:template match="/">
    <html><body>
       <xsl:apply-templates/>
    </body></html>
  </xsl:template>

  <xsl:template match="/ARTICLE/TITLE">
    <h1 align="center"> <xsl:apply-templates/> </h1>
  </xsl:template>

  <!-- Top Level Heading -->
  <xsl:template match="/ARTICLE/SECT">
      <h2> <xsl:apply-templates select="text()|B|I|U|DEF|LINK"/> </h2>
      <xsl:apply-templates select="SECT|PARA|LIST|NOTE"/>
  </xsl:template>
    
  <!-- Second-Level Heading -->
  <xsl:template match="/ARTICLE/SECT/SECT">
      <h3> <xsl:apply-templates select="text()|B|I|U|DEF|LINK"/> </h3>
      <xsl:apply-templates select="SECT|PARA|LIST|NOTE"/>
  </xsl:template>

  <!-- Third-Level Heading -->
  <xsl:template match="/ARTICLE/SECT/SECT/SECT">
     <xsl:message terminate="yes">Error: Sections can only be nested 2 deep.</xsl:message>
  </xsl:template>

  <!-- Paragraph -->
  <xsl:template match="PARA">
      <p><xsl:apply-templates/></p>
  </xsl:template>

</xsl:stylesheet>


