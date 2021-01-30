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
                <xsl:if test="string-length($value) &gt; 0">
                    <xsl:text>"</xsl:text>
                    <xsl:value-of select="$key"/>
                    <xsl:text>":"</xsl:text>
                    <xsl:value-of select="$value"/>
                    <xsl:text>",</xsl:text>
                </xsl:if>
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
        <xsl:text>":{</xsl:text>
        <xsl:value-of select="$child"/>
        <xsl:text>},</xsl:text>
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
        <xsl:call-template name="array">
            <xsl:with-param name="key">prescripts</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:apply-templates select="/nmaprun/prescript"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="array">
            <xsl:with-param name="key">postscripts</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:apply-templates select="/nmaprun/postscript"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:call-template name="array">
            <xsl:with-param name="key">hosthint</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:apply-templates select="/nmaprun/hosthint"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:apply-templates select="/nmaprun/runstats"/>
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
            <xsl:call-template name="array">
                <xsl:with-param name="key">hostscripts</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="hostscript"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:call-template name="array">
                <xsl:with-param name="key">ports</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:for-each select="ports">
                        <xsl:for-each select="port">
                            <xsl:call-template name="port">
                                <xsl:with-param name="port"/>
                            </xsl:call-template>
                        </xsl:for-each>
                    </xsl:for-each>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:call-template name="array">
                <xsl:with-param name="key">extraports</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:for-each select="ports">
                        <xsl:for-each select="extraports">
                            <xsl:call-template name="extraports">
                                <xsl:with-param name="extraports"/>
                            </xsl:call-template>
                        </xsl:for-each>
                    </xsl:for-each>
                </xsl:with-param>
            </xsl:call-template>

            <xsl:call-template name="array">
                <xsl:with-param name="key">traces</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="trace"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:apply-templates select="times"/>

            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>


    <!-- Port -->
    <xsl:template name="port">
        <xsl:param name="port"/>
        <xsl:text>{</xsl:text>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">protocol</xsl:with-param>
            <xsl:with-param name="value" select="@protocol"/>
        </xsl:call-template>
        <xsl:call-template name="int-arg-required">
            <xsl:with-param name="key">portid</xsl:with-param>
            <xsl:with-param name="value" select="@portid"/>
        </xsl:call-template>
        <xsl:call-template name="dict">
            <xsl:with-param name="key">state</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:apply-templates select="state"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:apply-templates select="owner"/>
        <xsl:apply-templates select="service"/>

        <xsl:call-template name="array">
            <xsl:with-param name="key">scripts</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:for-each select="script">
                    <xsl:apply-templates select="."/>

                </xsl:for-each>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:text>},</xsl:text>
    </xsl:template>

    <!-- extraports -->
    <xsl:template name="extraports">
        <xsl:param name="extraports"/>
        <xsl:text>{</xsl:text>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">state</xsl:with-param>
            <xsl:with-param name="value" select="@state"/>
        </xsl:call-template>
        <xsl:call-template name="int-arg-required">
            <xsl:with-param name="key">count</xsl:with-param>
            <xsl:with-param name="value" select="@count"/>
        </xsl:call-template>
        <xsl:call-template name="array">
            <xsl:with-param name="key">extrareasons</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:for-each select="extrareasons">
                    <xsl:call-template name="extrareasons">
                        <xsl:with-param name="extrareasons"/>
                    </xsl:call-template>
                </xsl:for-each>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:text>},</xsl:text>
    </xsl:template>

    <!-- extrareasons -->
    <xsl:template name="extrareasons">
        <xsl:param name="extrareasons"/>
        <xsl:text>{</xsl:text>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">reason</xsl:with-param>
            <xsl:with-param name="value" select="@reason"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">count</xsl:with-param>
            <xsl:with-param name="value" select="@count"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-optional">
            <xsl:with-param name="key">proto</xsl:with-param>
            <xsl:with-param name="value" select="@proto"/>
        </xsl:call-template>
        <xsl:call-template name="string-arg-optional">
            <xsl:with-param name="key">ports</xsl:with-param>
            <xsl:with-param name="value" select="@ports"/>
        </xsl:call-template>
        <xsl:text>},</xsl:text>
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

    <!-- state -->
    <xsl:template match="state" name="state">
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
        <xsl:call-template name="string-arg-required">
            <xsl:with-param name="key">reason_ip</xsl:with-param>
            <xsl:with-param name="value" select="@reason_ip"/>
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
        <xsl:call-template name="array">
            <xsl:with-param name="key">osclass</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:apply-templates select="osclass"/>
            </xsl:with-param>
        </xsl:call-template>
        <xsl:text>},</xsl:text>
    </xsl:template>

    <!-- osclass -->
    <xsl:template match="osclass" name="osclass">

        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">vendor</xsl:with-param>
                <xsl:with-param name="value" select="@vendor"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">osfamily</xsl:with-param>
                <xsl:with-param name="value" select="@osfamily"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-required">
                <xsl:with-param name="key">accuracy</xsl:with-param>
                <xsl:with-param name="value" select="@accuracy"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">osgen</xsl:with-param>
                <xsl:with-param name="value" select="@osgen"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">type</xsl:with-param>
                <xsl:with-param name="value" select="@type"/>
            </xsl:call-template>
            <xsl:call-template name="array">
                <xsl:with-param name="key">cpes</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:for-each select="cpe">
                        <xsl:text>"</xsl:text>
                        <xsl:value-of select="."/>
                        <xsl:text>",</xsl:text>
                    </xsl:for-each>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
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

    <!-- scripts -->
    <xsl:template match="hostscript" name="hostscript">
        <xsl:apply-templates select="script"/>
    </xsl:template>
    <xsl:template match="postscript" name="postscript">
        <xsl:apply-templates select="script"/>
    </xsl:template>
    <xsl:template match="prescript" name="prescript">
        <xsl:apply-templates select="script"/>
    </xsl:template>


    <xsl:template match="script" name="script">
        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">id</xsl:with-param>
                <xsl:with-param name="value" select="@id"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">output</xsl:with-param>
                <xsl:with-param name="value" select="@output"/>
            </xsl:call-template>

            <xsl:call-template name="array">
                <xsl:with-param name="key">tables</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="table"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:call-template name="array">
                <xsl:with-param name="key">elements</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="elem"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <xsl:template match="table" name="table">
        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">key</xsl:with-param>
                <xsl:with-param name="value" select="@key"/>
            </xsl:call-template>

            <xsl:call-template name="array">
                <xsl:with-param name="key">tables</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="table"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:call-template name="array">
                <xsl:with-param name="key">elements</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="elem"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- element -->
    <xsl:template match="elem" name="elem">
        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">value</xsl:with-param>
                <xsl:with-param name="value">
                    <xsl:value-of select="."/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">key</xsl:with-param>
                <xsl:with-param name="value" select="@key"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>


    <!-- hosthint -->
    <xsl:template match="hosthint" name="hosthint">
        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="dict">
                <xsl:with-param name="key">status</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="status"/>
                </xsl:with-param>
            </xsl:call-template>


            <xsl:call-template name="array">
                <xsl:with-param name="key">addresses</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="address"/>
                </xsl:with-param>
            </xsl:call-template>

            <xsl:apply-templates select="hostnames"/>


            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- runstats -->
    <xsl:template match="runstats" name="runstats">
        <xsl:call-template name="dict">
            <xsl:with-param name="key">runstats</xsl:with-param>
            <xsl:with-param name="child">
                <xsl:call-template name="int-arg-required">
                    <xsl:with-param name="key">up</xsl:with-param>
                    <xsl:with-param name="value" select="hosts/@up"/>
                </xsl:call-template>
                <xsl:call-template name="int-arg-required">
                    <xsl:with-param name="key">down</xsl:with-param>
                    <xsl:with-param name="value" select="hosts/@down"/>
                </xsl:call-template>
                <xsl:call-template name="int-arg-required">
                    <xsl:with-param name="key">total</xsl:with-param>
                    <xsl:with-param name="value" select="hosts/@total"/>
                </xsl:call-template>
                <xsl:call-template name="int-arg-required">
                    <xsl:with-param name="key">elapsed</xsl:with-param>
                    <xsl:with-param name="value" select="finished/@elapsed"/>
                </xsl:call-template>
                <xsl:call-template name="int-arg-required">
                    <xsl:with-param name="key">time</xsl:with-param>
                    <xsl:with-param name="value" select="finished/@time"/>
                </xsl:call-template>
                <xsl:call-template name="string-arg-optional">
                    <xsl:with-param name="key">timestr</xsl:with-param>
                    <xsl:with-param name="value" select="finished/@timestr"/>
                </xsl:call-template>
                <xsl:call-template name="string-arg-optional">
                    <xsl:with-param name="key">summary</xsl:with-param>
                    <xsl:with-param name="value" select="finished/@summary"/>
                </xsl:call-template>
                <xsl:call-template name="string-arg-optional">
                    <xsl:with-param name="key">exit</xsl:with-param>
                    <xsl:with-param name="value" select="finished/@exit"/>
                </xsl:call-template>
                <xsl:call-template name="string-arg-optional">
                    <xsl:with-param name="key">errormsg</xsl:with-param>
                    <xsl:with-param name="value" select="finished/@errormsg"/>
                </xsl:call-template>
            </xsl:with-param>
        </xsl:call-template>
    </xsl:template>


    <!-- trace -->
    <xsl:template match="trace" name="trace">
        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">proto</xsl:with-param>
                <xsl:with-param name="value" select="@proto"/>
            </xsl:call-template>
            <xsl:call-template name="int-arg-optional">
                <xsl:with-param name="key">port</xsl:with-param>
                <xsl:with-param name="value" select="@port"/>
            </xsl:call-template>

            <xsl:call-template name="array">
                <xsl:with-param name="key">hops</xsl:with-param>
                <xsl:with-param name="child">
                    <xsl:apply-templates select="hop"/>
                </xsl:with-param>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>

    <!-- hop -->
    <xsl:template match="hop" name="hop">
        <xsl:for-each select=".">
            <xsl:text>{</xsl:text>
            <xsl:call-template name="string-arg-required">
                <xsl:with-param name="key">ttl</xsl:with-param>
                <xsl:with-param name="value" select="@ttl"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">rtt</xsl:with-param>
                <xsl:with-param name="value" select="@rtt"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">host</xsl:with-param>
                <xsl:with-param name="value" select="@host"/>
            </xsl:call-template>
            <xsl:call-template name="string-arg-optional">
                <xsl:with-param name="key">ipaddr</xsl:with-param>
                <xsl:with-param name="value" select="@ipaddr"/>
            </xsl:call-template>
            <xsl:text>},</xsl:text>
        </xsl:for-each>
    </xsl:template>
    <!-- times -->
    <xsl:template match="times" name="times">
        <xsl:choose>
            <xsl:when test=".">
                <xsl:call-template name="dict">
                    <xsl:with-param name="key">times</xsl:with-param>
                    <xsl:with-param name="child">
                        <xsl:call-template name="string-arg-required">
                            <xsl:with-param name="key">srtt</xsl:with-param>
                            <xsl:with-param name="value" select="@srtt"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-required">
                            <xsl:with-param name="key">rttvar</xsl:with-param>
                            <xsl:with-param name="value" select="@rttvar"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-required">
                            <xsl:with-param name="key">to</xsl:with-param>
                            <xsl:with-param name="value" select="@to"/>
                        </xsl:call-template>
                    </xsl:with-param>
                </xsl:call-template>
            </xsl:when>
        </xsl:choose>
    </xsl:template>

    <!-- owner -->
    <xsl:template match="owner" name="owner">
        <xsl:choose>
            <xsl:when test=".">
                <xsl:call-template name="string-arg-required">
                    <xsl:with-param name="key">owner</xsl:with-param>
                    <xsl:with-param name="value" select="@name"/>
                </xsl:call-template>
            </xsl:when>
        </xsl:choose>
    </xsl:template>


    <!-- service -->
    <xsl:template match="service" name="service">
        <xsl:choose>
            <xsl:when test=".">
                <xsl:call-template name="dict">
                    <xsl:with-param name="key">service</xsl:with-param>
                    <xsl:with-param name="child">


                        <xsl:call-template name="string-arg-required">
                            <xsl:with-param name="key">name</xsl:with-param>
                            <xsl:with-param name="value" select="@name"/>
                        </xsl:call-template>
                        <xsl:call-template name="int-arg-required">
                            <xsl:with-param name="key">conf</xsl:with-param>
                            <xsl:with-param name="value" select="@conf"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-required">
                            <xsl:with-param name="key">method</xsl:with-param>
                            <xsl:with-param name="value" select="@method"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">version</xsl:with-param>
                            <xsl:with-param name="value" select="@version"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">product</xsl:with-param>
                            <xsl:with-param name="value" select="@product"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">extrainfo</xsl:with-param>
                            <xsl:with-param name="value" select="@extrainfo"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">tunnel</xsl:with-param>
                            <xsl:with-param name="value" select="@tunnel"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">proto</xsl:with-param>
                            <xsl:with-param name="value" select="@proto"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">rpcnum</xsl:with-param>
                            <xsl:with-param name="value" select="@rpcnum"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">lowver</xsl:with-param>
                            <xsl:with-param name="value" select="@lowver"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">highver</xsl:with-param>
                            <xsl:with-param name="value" select="@highver"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">hostname</xsl:with-param>
                            <xsl:with-param name="value" select="@hostname"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">ostype</xsl:with-param>
                            <xsl:with-param name="value" select="@ostype"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">devicetype</xsl:with-param>
                            <xsl:with-param name="value" select="@devicetype"/>
                        </xsl:call-template>
                        <xsl:call-template name="string-arg-optional">
                            <xsl:with-param name="key">servicefp</xsl:with-param>
                            <xsl:with-param name="value" select="@servicefp"/>
                        </xsl:call-template>
                    </xsl:with-param>
                </xsl:call-template>
            </xsl:when>
        </xsl:choose>
    </xsl:template>
</xsl:stylesheet>
