<xsl:template match="mylink">
    <a>
     <xsl:for-each select="@*">
      <xsl:if test="name() != 'type'">
       <xsl:attribute name="{name()}"><xsl:value-of select="."/></xsl:attribute>
      </xsl:if> 
     </xsl:for-each>
    </a>
</xsl:template>
