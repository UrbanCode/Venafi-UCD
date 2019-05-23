package com.urbancode.air

import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.client.methods.HttpGet

import com.urbancode.commons.httpcomponentsutil.HttpClientBuilder

import groovyx.net.http.RESTClient
import groovyx.net.http.ContentType
import static groovyx.net.http.ContentType.JSON
import groovy.json.JsonOutput
import groovyx.net.http.AuthConfig

import javax.net.ssl.SSLContext

import org.apache.http.conn.scheme.SchemeSocketFactory
import org.apache.http.conn.ssl.SSLSocketFactory

import javax.net.ssl.X509TrustManager
import javax.net.ssl.TrustManager

import org.apache.http.conn.scheme.Scheme
import org.apache.http.HttpResponse

import com.urbancode.air.UCDServerConnection
import org.codehaus.jettison.json.JSONObject
import org.codehaus.jettison.json.JSONArray
import groovy.json.JsonSlurper

class httpRequestProcess {
	HttpClientBuilder clientBuilder
	DefaultHttpClient client
	UCDServerConnection serverConnection
	int counter
	boolean debug

	httpRequestProcess(UCDServerConnection serverConnection, boolean debug) {
		this.serverConnection = serverConnection

		clientBuilder = new HttpClientBuilder()
		clientBuilder.setUsername(serverConnection.getUserName())
		clientBuilder.setPassword(serverConnection.getPassword())
		clientBuilder.setTrustAllCerts(true)
		client = clientBuilder.buildClient()
		this.debug = debug
		counter = 0
	}

	public String httpGetResource(String resourceID) {
		String completeURL = serverConnection.getWebURL() + "/rest/resource/resource/" + resourceID + "/resources"

		return(httpGet(completeURL))

	}

	public String httpGetResourceProps(String propSheet, Integer version) {

		def urlPropSheet = propSheet.replaceAll("/", "%26")
		String completeURL = serverConnection.getWebURL() + "/property/propSheet/" + urlPropSheet + "." + version.toString()

		return(httpGet(completeURL))
	}

	private String httpGet(String url) {
		HttpGet request = new HttpGet(new URI(url))
		HttpResponse resp = client.execute(request)
		BufferedReader br = new BufferedReader (new InputStreamReader(resp.getEntity().getContent()))
		String responseText = ""

		String currentLine = new String();

		while ((currentLine = br.readLine()) != null){
			responseText += currentLine
		}
		return(responseText)

	}
}
