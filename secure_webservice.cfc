<cfcomponent>

	<!---
    The WSS4CF Library
    Copyright (C) 2010 James Holmes

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
	and the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    --->

	<cffunction name="init" access="public" output="false" returntype="any" hint="Wraps a webservice object to provide WS-SECURITY for the calls">
		<cfargument name="wsdl" type="string" required="yes" hint="The wsdl URL">
		<cfset variables.ws = createObject("webservice",arguments.wsdl)>
		<cfset variables.passwordType = "">
        <cfreturn this>
	</cffunction>
    
    <cffunction name="setCredentials" access="public" output="false" returntype="void" hint="Set the username and password to use in the WSSE header">
    	<cfargument name="userName" required="true" type="string" hint="The username">
        <cfargument name="password" required="true" type="string" hint="The password">
        <cfargument name="passwordType" required="false" default="PasswordText" hint="The password type, either 'PasswordText' or 'PasswordDigest'">
        <cfset variables.username = arguments.username>
        <cfset variables.password = arguments.password>
        <cfswitch expression="#arguments.passwordType#">
        	<cfcase value="PasswordText,PasswordDigest">
            	<cfset variables.passwordType = arguments.passwordType>
            </cfcase>
            <cfdefaultcase>
            	<cfthrow message="Incorrect Password Type" detail="The password type #arguments.passwordType# is not supported; specify either 'PasswordText' or 'PasswordDigest'">
            </cfdefaultcase>
        </cfswitch>
    </cffunction>
    
    <cffunction name="getDigest" access="public" output="false" returntype="string" hint="Creates the digest password.">
    	<cfargument name="password" required="true" type="string" hint="The plain text version of the password">
        <cfargument name="created" required="true" type="string" hint="The text version of the utc formatted creation date">
        <cfargument name="nonce" required="true" type="string" hint="The base64 encoded nonce">
        <cfset var nonceBin = binaryDecode(arguments.nonce,"base64")>
		<cfset var nonceEnc = binaryEncode(nonceBin,"hex")>
        <cfset var pwEnc = binaryEncode(charsetDecode(arguments.password,"utf-8"),"hex")>
        <cfset var crEnc = binaryEncode(charsetDecode(arguments.created,"utf-8"),"hex")>
        <cfset var concatBin = binaryDecode(nonceEnc&crEnc&pwEnc,"hex")>
        <cfset var md = createObject("java","java.security.MessageDigest").getInstance("SHA-1")>
		<cfset md.reset()>
        <cfset md.update(concatBin)>
        <cfreturn binaryEncode(md.digest(),"base64")>
    </cffunction>
	
	<cffunction name="getWSSEHeader" access="public" output="false" returntype="xml" hint="Creates a WSSE header with a UsernameToken">
		<cfargument name="username" required="true" type="string" hint="The username to include in the header">
		<cfargument name="password" required="true" type="string" hint="The password to use in generating the header">
		<cfargument name="passwordType" required="true" type="string" hint="The password type; either 'PasswordText' or 'PasswordDigest' can be specified">
		<cfargument name="nonce" type="string" required="false" default="" hint="The base64 encoded nonce to use in the header; required if the digest password type is chosen">
		<cfargument name="creationTime" type="date" required="false" default="#now()#" hint="The local creation time for the header; defaults to the current time">
		<cfargument name="ttl" type="numeric" required="false" default="300" hint="The number of seconds before the header expires; defaults to 300s (5 minutes)">
		<cfset var utcTime = dateConvert("local2utc",arguments.creationTime)>
		<cfset var created =  formatXMLDateTime(utcTime)>
        <cfset var expires = formatXMLDateTime(dateAdd("s",arguments.ttl,utcTime))>
        <cfset var wsseHeader = "">
        <cfset var headerPassword = "">
		<cfswitch expression="#arguments.passwordType#">
        	<cfcase value="PasswordText">
            	<cfset headerPassword = arguments.password>
            </cfcase>
            <cfcase value="PasswordDigest">
            	<cfset headerPassword = getDigest(arguments.password,created,arguments.nonce)>
            </cfcase>
            <cfdefaultcase>
            	<cfthrow message="Incorrect Password Type" detail="The password type #arguments.passwordType# is not supported; specify either 'PasswordText' or 'PasswordDigest'">
            </cfdefaultcase>
        </cfswitch>
		<cfxml variable="wsseHeader" casesensitive="true">
			<cfoutput>
                <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="#createuuid()#">
                        <wsu:Created>#created#</wsu:Created>
                        <wsu:Expires>#expires#</wsu:Expires>
                    </wsu:Timestamp>
                    <wsse:UsernameToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="#createuuid()#">
                        <wsse:Username>#arguments.username#</wsse:Username>
                        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0###arguments.passwordType#">#headerPassword#</wsse:Password>
                    <cfif arguments.passwordType IS "PasswordDigest">
                        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0##Base64Binary">#arguments.nonce#</wsse:Nonce>
                        <wsu:Created>#created#</wsu:Created>
                    </cfif>
                    </wsse:UsernameToken>
                </wsse:Security>
            </cfoutput>
        </cfxml>
		<cfreturn wsseHeader>
	</cffunction>
	
	<cffunction name="formatXMLDateTime" access="public" output="false" returntype="string" hint="Takes a date and formats it for use in a SOAP header">
		<cfargument name="dateTime" required="true" type="date" hint="The date to format">
		<cfset var formattedDateTime = dateformat(arguments.dateTime,"yyyy-mm-dd")&"T"&timeFormat(arguments.dateTime,"HH:mm:ss.L")&"Z">
		<cfreturn formattedDateTime>
	</cffunction>
    
    <cffunction	name="onMissingMethod" access="public" returntype="any" output="false" hint="Handles missing method exceptions.">
        <cfargument name="missingMethodName" type="string" required="true" hint="The name of the ws method to call."/>
        <cfargument name="missingMethodArguments" type="struct" required="true" hint="The arguments that were passed to the ws method. Requires named arguments in this case."/>
     	<cfset var wsResult = "">
        <cfset var currentArgument = "">
		<!--- first add a header --->
        <cfset addWSSEHeader()>
		<!--- then call the method on the ws --->
        <cfinvoke webservice="#variables.ws#" method="#arguments.missingMethodName#" returnvariable="wsResult">
            <cfloop collection="#arguments.missingMethodArguments#" item="currentArgument">
            	<cfif isNumeric(currentArgument)>
                	<cfthrow message="Argument not named" detail="Argument #currentArgument# was not given a name. Use named arguments for all method calls">
                </cfif>
                <cfinvokeargument name="#currentArgument#" value="#arguments.missingMethodArguments[currentArgument]#">
            </cfloop>
        </cfinvoke>
        <cfparam name="wsResult" default="">
        <cfreturn wsResult>
    </cffunction>
    
    <cffunction name="addWSSEHeader" access="private" output="false" returntype="any" hint="Adds the WSSE header to the instance webservice object">
    	<cfset var utcTime = dateConvert("local2utc",now())>
		<cfset var created = dateformat(utcTime,"yyyy-mm-dd")&"T"&timeFormat(utcTime,"HH:mm:ss.L")&"Z">
        <cfset var expires = dateformat(dateAdd("n",5,utcTime),"yyyy-mm-dd")&"T"&timeFormat(dateAdd("n",5,utcTime),"HH:mm:ss.L")&"Z">
		<cfset var headers = "">
		<cfset var wsseHeader = "">
		<cfif NOT structKeyExists(variables,"ws")>
			<cfthrow message="Not Initialised" detail="You must call init() and pass in a valid WSDL URL before security headers can be added to your webservice">
		</cfif>
		<cfif variables.passwordType IS "">
			<cfthrow message="Credentials Not Set" detail="You must call setCredentials() before security headers can be added to your webservice">
		<cfelse>
			<cfset wsseHeader = getWSSEHeader(variables.username,variables.password,variables.passwordType,createNonce())>
		</cfif>
        <cfset AddSOAPRequestHeader(variables.ws,"dummy","dummy",wsseHeader)>
		<cfset headers = variables.ws.getHeaders()>
        <cfset headers[1].setActor(JavaCast("null", ""))>
    </cffunction>
    
    <cffunction name="createNonce" access="private" output="false" returntype="string" hint="Creates a base64 encoded nonce">
    	<cfset var nonceString = "#createuuid()#">
		<cfset var nonceBinary = charsetDecode(nonceString,"utf-8")>
        <cfset var nonceBase64 = binaryEncode(nonceBinary,"base64")>
        <cfreturn nonceBase64>
    </cffunction>
    
    
</cfcomponent>