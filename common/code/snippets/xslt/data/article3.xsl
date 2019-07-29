<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
  version="1.0"
  >
  <xsl:output method="html"/> 
  <xsl:strip-space elements="SECT"/>

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
    <p> <xsl:apply-templates select="text()|B|I|U|DEF|LINK"/> </p>
    <xsl:apply-templates select="PARA|LIST|NOTE"/>
  </xsl:template>

  <!-- Text -->
<!-- 
  <xsl:template match="text()">
    <xsl:value-of select="normalize-space()"/>
  </xsl:template>
-->

  <!-- LIST  -->
  <xsl:template match="LIST">
    <xsl:if test="@type='ordered'">
      <ol>
      <xsl:apply-templates/>
      </ol>
    </xsl:if>
    <xsl:if test="@type='unordered'">
      <ul>
      <xsl:apply-templates/>
      </ul>
    </xsl:if>
  </xsl:template>

  <!-- list ITEM -->
  <xsl:template match="ITEM">
    <li><xsl:apply-templates/>
    </li>
  </xsl:template>

  <xsl:template match="NOTE">
    <blockquote><b>Note:</b><br/>
      <xsl:apply-templates/>
    </blockquote>
  </xsl:template>

  <xsl:template match="DEF">
     <i> <xsl:apply-templates/> </i>   
  </xsl:template>

  <xsl:template match="B|I|U">
     <xsl:element name="{name()}">
       <xsl:apply-templates/>
     </xsl:element> 
  </xsl:template>

  <xsl:template match="LINK">
    <xsl:if test="@target">
      <!--Target attribute specified.-->
      <xsl:call-template name="htmLink">
        <xsl:with-param name="dest" select="@target"/>  <!--Destination = attribute value-->
      </xsl:call-template>
    </xsl:if>

    <xsl:if test="not(@target)">
      <!--Target attribute not specified.-->
      <xsl:call-template name="htmLink">
        <xsl:with-param name="dest">
          <xsl:apply-templates/>  <!--Destination value = text of node-->
        </xsl:with-param>
      </xsl:call-template>
    </xsl:if>
  </xsl:template>

  <!-- A named template that constructs an HTML link -->
  <xsl:template name="htmLink">
    <xsl:param name="dest" select="UNDEFINED"/> <!--default value-->
    <xsl:element name="a">
      <xsl:attribute name="href">
        <xsl:value-of select="$dest"/> <!--link target-->
      </xsl:attribute>
      <xsl:apply-templates/> <!--name of the link from text of node-->
    </xsl:element> 
  </xsl:template>

</xsl:stylesheet>


