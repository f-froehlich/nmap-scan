<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:output method="text" encoding="utf-8" indent="yes" doctype-system="about:legacy-compat"/>
    <xsl:template name="string-arg-required">
        <xsl:param name="key"/>
        <xsl:param name="value"/>
        <xsl:text>"</xsl:text>
        <xsl:value-of select="$key"/>
        <xsl:text>":"</xsl:text>
        <xsl:value-of select="$value"/>
        <xsl:text>",</xsl:text>
    </xsl:template>
    <xsl:template name="string-arg-optional">
        <xsl:param name="key"/>
        <xsl:param name="value"/>
        <xsl:choose>
            <xsl:when test="$key">
                <xsl:text>"</xsl:text>
                <xsl:value-of select="$key"/>
                <xsl:text>":"</xsl:text>
                <xsl:value-of select="$value"/>
                <xsl:text>",</xsl:text>
            </xsl:when>
        </xsl:choose>
    </xsl:template>
    <xsl:template name="int-arg-required">
        <xsl:param name="key"/>
        <xsl:param name="value"/>
        <xsl:text>"</xsl:text>
        <xsl:value-of select="$key"/>
        <xsl:text>":</xsl:text>
        <xsl:value-of select="$value"/>
        <xsl:text>,</xsl:text>
    </xsl:template>
    <xsl:template name="int-arg-optional">
        <xsl:param name="key"/>
        <xsl:param name="value"/>
        <xsl:choose>
            <xsl:when test="$key">
                <xsl:text>"</xsl:text>
                <xsl:value-of select="$key"/>
                <xsl:text>":</xsl:text>
                <xsl:value-of select="$value"/>
                <xsl:text>,</xsl:text>
            </xsl:when>
        </xsl:choose>
    </xsl:template>
    <xsl:template name="array">
        <xsl:param name="key"/>
        <xsl:param name="child"/>
        <xsl:text>"</xsl:text>
        <xsl:value-of select="$key"/>
        <xsl:text>":[</xsl:text>
        <xsl:value-of select="$child"/>
        <xsl:text>],</xsl:text>
    </xsl:template>
    <xsl:template name="dict">
        <xsl:param name="key"/>
        <xsl:param name="child"/>
        <xsl:text>"</xsl:text>
        <xsl:value-of select="$key"/>
        <xsl:text>":[</xsl:text>
        <xsl:value-of select="$child"/>
        <xsl:text>],</xsl:text>
    </xsl:template>


    <!-- Nmaprun -->
    <xsl:template match="/" name="nmaprun">
        <xsl:text>{</xsl:text>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">scanner</xsl:with-param>
            <xsl:with-param name="value" select="/nmaprun/@scanner"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">version</xsl:with-param>
            <xsl:with-param name="value" select="/nmaprun/@version"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">xmloutputversion</xsl:with-param>
            <xsl:with-param name="value" select="/nmaprun/@xmloutputversion"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-optional">
            <xsl:with-param name="key">args</xsl:with-param>
            <xsl:with-param name="value" select="/nmaprun/@args"/>
        </xsl:call-template>
        <xsl:call-template name="int-arg-optional">
            <xsl:with-param name="key">start</xsl:with-param>
            <xsl:with-param name="value" select="/nmaprun/@start"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-optional">
            <xsl:with-param name="key">startstr</xsl:with-param>
            <xsl:with-param name="value" select="/nmaprun/@startstr"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-optional">
            <xsl:with-param name="key">profile_name</xsl:with-param>
            <xsl:with-param name="value" select="/nmaprun/@profile_name"/>
        </xsl:call-template>
        <xsl:call-template name="array">
            <xsl:with-param name="key">scaninfo</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:call-template name="scaninfo"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="verbose"/>
        <xsl:call-template name="debugging"/>
        <xsl:call-template name="array">
            <xsl:with-param name="key">targets</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:call-template name="targets"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="array">
            <xsl:with-param name="key">taskbegin</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:call-template name="taskbegin"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="array">
            <xsl:with-param name="key">taskprogress</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:call-template name="taskprogress"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="array">
            <xsl:with-param name="key">taskend</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:call-template name="taskend"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="array">
            <xsl:with-param name="key">hosts</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:call-template name="hosts"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:text>}</xsl:text>
    </xsl:template>


    <!-- Scaninfo -->
    <xsl:template name="scaninfo">
        <xsl:for-each select="/nmaprun/scaninfo">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">type</xsl:with-param>
                <xsl:with-param name="value" select="@type"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">protocol</xsl:with-param>
                <xsl:with-param name="value" select="@protocol"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">numservices</xsl:with-param>
                <xsl:with-param name="value" select="@numservices"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">services</xsl:with-param>
                <xsl:with-param name="value" select="@services"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">scanflags</xsl:with-param>
                <xsl:with-param name="value" select="@scanflags"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- Verbose -->
    <xsl:template name="verbose">
        <xsl:call-template name="int-arg-optional">
            <xsl:with-param name="key">verbose</xsl:with-param>
            <xsl:with-param name="value" select="/nmaprun/verbose/@level"/>
        </xsl:call-template>
    </xsl:template>

    <!-- Debugging -->
    <xsl:template name="debugging">
        <xsl:call-template name="int-arg-optional">
            <xsl:with-param name="key">debugging</xsl:with-param>
            <xsl:with-param name="value" select="/nmaprun/debugging/@level"/>
        </xsl:call-template>
    </xsl:template>


    <!-- Target -->
    <xsl:template name="targets">
        <xsl:for-each select="/nmaprun/target">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">specification</xsl:with-param>
                <xsl:with-param name="value" select="@specification"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">status</xsl:with-param>
                <xsl:with-param name="value" select="@status"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">reason</xsl:with-param>
                <xsl:with-param name="key">reason</xsl:with-param>
                <xsl:with-param name="value" select="@reason"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>


    <!-- Taskbegin -->
    <xsl:template name="taskbegin">
        <xsl:for-each select="/nmaprun/taskbegin">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">task</xsl:with-param>
                <xsl:with-param name="value" select="@task"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">time</xsl:with-param>
                <xsl:with-param name="value" select="@time"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">extrainfo</xsl:with-param>
                <xsl:with-param name="value" select="@extrainfo"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- Taskprogress -->
    <xsl:template name="taskprogress">
        <xsl:for-each select="/nmaprun/taskprogress">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">task</xsl:with-param>
                <xsl:with-param name="value" select="@task"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">time</xsl:with-param>
                <xsl:with-param name="value" select="@time"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">percent</xsl:with-param>
                <xsl:with-param name="value" select="@percent"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">remaining</xsl:with-param>
                <xsl:with-param name="value" select="@remaining"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">etc</xsl:with-param>
                <xsl:with-param name="value" select="@etc"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>


    <!-- Taskend -->
    <xsl:template name="taskend">
        <xsl:for-each select="/nmaprun/taskend">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">task</xsl:with-param>
                <xsl:with-param name="value" select="@task"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">time</xsl:with-param>
                <xsl:with-param name="value" select="@time"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">extrainfo</xsl:with-param>
                <xsl:with-param name="value" select="@extrainfo"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- Hosts -->
    <xsl:template name="hosts">
        <xsl:for-each select="/nmaprun/host">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="int-arg-optional">
                <xsl:with-param name="key">starttime</xsl:with-param>
                <xsl:with-param name="value" select="@starttime"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-optional">
                <xsl:with-param name="key">endtime</xsl:with-param>
                <xsl:with-param name="value" select="@endtime"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">comment</xsl:with-param>
                <xsl:with-param name="value" select="@comment"/>
            </xsl:call-template>
            <xsl:call-template name="dict">
                <xsl:with-param name="key">status</xsl:with-param>
                <xsl:with-param name="child" select="status"/>
            </xsl:call-template>
            <xsl:call-template name="array">
                <xsl:with-param name="key">addresses</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="address"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:apply-templates select="hostnames"/>
            <xsl:apply-templates select="smurf"/>
            <xsl:apply-templates select="os"/>
            <xsl:call-template name="array">
                <xsl:with-param name="key">distances</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="distance"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:call-template name="array">
                <xsl:with-param name="key">uptime</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="uptime"/>
                </xsl:with-param>
            </xsl:call-template>

            <xsl:call-template name="array">
                <xsl:with-param name="key">tcpsequence</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="tcpsequence"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:call-template name="array">
                <xsl:with-param name="key">tcptssequence</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="tcptssequence"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:call-template name="array">
                <xsl:with-param name="key">ipidsequence</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="ipidsequence"/>
                </xsl:with-param>
            </xsl:call-template>

            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- Status -->
    <xsl:template match="status" name="status">
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">state</xsl:with-param>
            <xsl:with-param name="value" select="@state"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">reason</xsl:with-param>
            <xsl:with-param name="value" select="@reason"/>
        </xsl:call-template>
        <xsl:call-template name="int-arg-required">
            <xsl:with-param name="key">reason_ttl</xsl:with-param>
            <xsl:with-param name="value" select="@reason_ttl"/>
        </xsl:call-template>
    </xsl:template>

    <!-- Address -->
    <xsl:template match="address" name="address">
        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">addr</xsl:with-param>
                <xsl:with-param name="value" select="@addr"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">addrtype</xsl:with-param>
                <xsl:with-param name="value" select="@addrtype"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">vendor</xsl:with-param>
                <xsl:with-param name="value" select="@vendor"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- Hostnames -->
    <xsl:template match="hostnames" name="hostnames">
        <xsl:call-template name="array">
            <xsl:with-param name="key">hostnames</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:for-each select="hostname">
                    <xsl:text>{</xsl:text>
                    <xsl:call-template name="string-arg-optional">
                        <xsl:with-param name="key">name</xsl:with-param>
                        <xsl:with-param name="value" select="@name"/>
                    </xsl:call-template>
                    <xsl:call-template name="string-arg-optional">
                        <xsl:with-param name="key">type</xsl:with-param>
                        <xsl:with-param name="value" select="@type"/>
                    </xsl:call-template>
                    <xsl:text>},</xsl:text>
                </xsl:for-each>
            </xsl:with-param>
        </xsl:call-template>
    </xsl:template>


    <!-- Smurf -->
    <xsl:template match="smurf" name="smurfs">
        <xsl:call-template name="array">
            <xsl:with-param name="key">smurfs</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:for-each select=".">
                    <xsl:text>"</xsl:text>
                    <xsl:value-of select="@responses"/>
                    <xsl:text>",</xsl:text>
                </xsl:for-each>
            </xsl:with-param>
        </xsl:call-template>
    </xsl:template>

    <!-- OS -->
    <xsl:template match="os" name="os">
        <xsl:call-template name="array">
            <xsl:with-param name="key">os</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:for-each select=".">
                    <xsl:text>{</xsl:text>
                    <xsl:call-template name="array">
                        <xsl:with-param name="key">portused</xsl:with-param>
                        <xsl:with-param name="child">
                            <xsl:for-each select=".">
                                <xsl:apply-templates select="portused"/>
                            </xsl:for-each>
                        </xsl:with-param>
                    </xsl:call-template>
                    <xsl:call-template name="array">
                        <xsl:with-param name="key">osmatch</xsl:with-param>
                        <xsl:with-param name="child">
                            <xsl:for-each select=".">
                                <xsl:apply-templates select="osmatch"/>
                            </xsl:for-each>
                        </xsl:with-param>
                    </xsl:call-template>
                    <xsl:call-template name="array">
                        <xsl:with-param name="key">osfingerprint</xsl:with-param>
                        <xsl:with-param name="child">
                            <xsl:for-each select=".">
                                <xsl:apply-templates select="osfingerprint"/>
                            </xsl:for-each>
                        </xsl:with-param>
                    </xsl:call-template>
                    <xsl:text>},</xsl:text>
                </xsl:for-each>
            </xsl:with-param>
        </xsl:call-template>
    </xsl:template>

    <!-- portused -->
    <xsl:template match="portused" name="portused">
        <xsl:text>{</xsl:text>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">state</xsl:with-param>
            <xsl:with-param name="value" select="@state"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">proto</xsl:with-param>
            <xsl:with-param name="value" select="@proto"/>
        </xsl:call-template>
        <xsl:call-template name="int-arg-required">
            <xsl:with-param name="key">portid</xsl:with-param>
            <xsl:with-param name="value" select="@portid"/>
        </xsl:call-template>
        <xsl:text>},</xsl:text>
    </xsl:template>


    <!-- osmatch -->
    <xsl:template match="osmatch" name="osmatch">

        <xsl:text>{</xsl:text>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">name</xsl:with-param>
            <xsl:with-param name="value" select="@name"/>
        </xsl:call-template>
        <xsl:call-template name="int-arg-required">
            <xsl:with-param name="key">accuracy</xsl:with-param>
            <xsl:with-param name="value" select="@accuracy"/>
        </xsl:call-template>
        <xsl:call-template name="int-arg-required">
            <xsl:with-param name="key">line</xsl:with-param>
            <xsl:with-param name="value" select="@line"/>
        </xsl:call-template>
        <xsl:text>},</xsl:text>
    </xsl:template>

    <!-- osfingerprint -->
    <xsl:template match="osfingerprint" name="osfingerprint">

        <xsl:text>"</xsl:text>
        <xsl:value-of select="@fingerprint"/>
        <xsl:text>",</xsl:text>
    </xsl:template>


    <!-- distance -->
    <xsl:template match="distance" name="distance">

        <xsl:for-each select=".">
            <xsl:value-of select="@value"/>
            <xsl:text>,</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- uptime -->
    <xsl:template match="uptime" name="uptime">

        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">seconds</xsl:with-param>
                <xsl:with-param name="value" select="@seconds"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">lastboot</xsl:with-param>
                <xsl:with-param name="value" select="@lastboot"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- tcpsequence -->
    <xsl:template match="tcpsequence" name="tcpsequence">

        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">index</xsl:with-param>
                <xsl:with-param name="value" select="@index"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">difficulty</xsl:with-param>
                <xsl:with-param name="value" select="@difficulty"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">values</xsl:with-param>
                <xsl:with-param name="value" select="@values"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>
    <!-- ipidsequence -->
    <xsl:template match="ipidsequence" name="ipidsequence">

        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">class</xsl:with-param>
                <xsl:with-param name="value" select="@class"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">values</xsl:with-param>
                <xsl:with-param name="value" select="@values"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>
    <!-- tcptssequence -->
    <xsl:template match="tcptssequence" name="tcptssequence">

        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">class</xsl:with-param>
                <xsl:with-param name="value" select="@class"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">values</xsl:with-param>
                <xsl:with-param name="value" select="@values"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

</xsl:stylesheet>
