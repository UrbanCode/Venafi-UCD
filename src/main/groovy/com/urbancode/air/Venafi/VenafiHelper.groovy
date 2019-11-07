/*
 * Licensed Materials - Property of IBM Corp.
 * IBM UrbanCode Deploy
<<<<<<< HEAD
 * (c) Copyright IBM Corporation 2011, 2014. All Rights Reserved.
=======
 * (c) Copyright IBM Corporation 2017. All Rights Reserved.
>>>>>>> bcd33dde3bb541b4afbdb2de8f831a463496f986
 *
 * U.S. Government Users Restricted Rights - Use, duplication or disclosure restricted by
 * GSA ADP Schedule Contract with IBM Corp.
 */
package com.urbancode.air.Venafi

import groovy.json.JsonOutput

import java.util.UUID
import java.util.List
import java.util.Map
import java.util.HashMap
import java.util.regex.Pattern
import java.util.Properties
import java.time.*
import java.text.SimpleDateFormat
import groovy.time.TimeCategory

import org.codehaus.jettison.json.JSONObject
import org.codehaus.jettison.json.JSONArray
import groovy.json.JsonSlurper

import com.urbancode.air.AirPluginTool
import com.urbancode.ud.client.AgentClient
import com.urbancode.ud.client.ResourceClient
import com.urbancode.ud.client.EnvironmentClient
import com.urbancode.commons.util.FileFilterToRegex

import com.urbancode.air.Venafi.httpRequestProcess
import com.urbancode.air.Venafi.CSR
import com.urbancode.air.UCDServerConnection

import org.apache.http.HttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.DefaultHttpClient

import com.urbancode.commons.httpcomponentsutil.HttpClientBuilder

import com.urbancode.air.Venafi.VenafiRESTAPI
import com.urbancode.air.Venafi.CustomField
import com.urbancode.air.Venafi.CustomFields

import java.security.*

import groovyx.net.http.RESTClient
import java.security.cert.CertificateException
// import static groovyx.net.http.ContentType.*
import java.security.cert.X509Certificate

public class VenafiHelper {
  def apTool
  def props = []
  def udUser
  def udPass
  def weburl
  UCDServerConnection serverConnection

  VenafiRESTAPI tpp = new VenafiRESTAPI()

  CustomFields customFields = new CustomFields()

  public VenafiHelper(def apToolIn) {
      apTool = apToolIn
      props = apTool.getStepProperties()
      udUser = apTool.getAuthTokenUsername()
      udPass = apTool.getAuthToken()
      weburl = System.getenv("AH_WEB_URL")
      com.urbancode.air.XTrustProvider.install()

      serverConnection = new UCDServerConnection(weburl, udUser, udPass)

  }

  private static List<Pattern> getGlobPatternsFromMultiline(String multiline) {
      return multiline.split("\n")
              .findAll({ it.trim().length() > 0 })
              .collect({ FileFilterToRegex.convert(it) })
  }

  def authenticate() {
    def tppURL = props['tppURL'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Authentication test     ~~")
    println("~~ Parameters              ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL      : " + tppURL)
    println("tppUser     : " + tppUser)
    println("tppPassword : " + tppPassword)

    def request = tpp.authenticate(tppURL, tppUser, tppPassword)
    if (request.APIKey.length() > 0) {
      println("API Key obtained successfully")
    }

    def requestDate = request.ValidUntil
    String requestDateString = new String(request.ValidUntil)
    requestDateString = requestDateString.substring(6, requestDateString.length() - 2)

    Long dateAsInteger = requestDateString.toLong()

    def tz= TimeZone.'default'
    dateAsInteger = dateAsInteger.minus(tz.rawOffset)
    String newDate = new Date(dateAsInteger).toString()  //get a string back
    println("API Key expires at : " + newDate)
    apTool.setOutputProperties()
  }

  def getVenafiPolicy() {
    def tppURL = props['tppURL'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()
    def policyDN = props['policyDN'].trim()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Get Venafi policy       ~~")
    println("~~ Parameters              ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL   : " + tppURL)
    println("tppUser  : " + tppUser)
    println("policyDN : " + policyDN)

    String city = ""
    String state = ""
    String country = ""
    String organization = ""
    String organizationalUnit = ""
    String keyBitStrength = ""
    Integer keyBitStrengthInt = 0
    String managementType = ""
    String manualCSR = ""
    String certificateAuthority = ""
    String keyAlgorithm = ""

    Boolean policyFailed = false
    String policyFailMessage = "Policy error reading value for : "

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    HashMap policy = checkPolicy(tppURL, apikey, policyDN)
    JSONObject jsonPolicy = new JSONObject(policy)

    city = jsonPolicy.Policy.Subject.City.Value
    state = jsonPolicy.Policy.Subject.State.Value
    country = jsonPolicy.Policy.Subject.Country.Value
    organization = jsonPolicy.Policy.Subject.Organization.Value
    organizationalUnit = jsonPolicy.Policy.Subject.OrganizationalUnit.Values[0]
    keyAlgorithm = jsonPolicy.Policy.KeyPair.KeyAlgorithm.Value
    keyBitStrength = jsonPolicy.Policy.KeyPair.KeySize.Value
    if (keyBitStrength.length() > 0) {
      keyBitStrengthInt = keyBitStrength.toInteger()
    }
    managementType = jsonPolicy.Policy.ManagementType.Value
    manualCSR = jsonPolicy.Policy.CsrGeneration.Value

    (certificateAuthority, policyFailed, policyFailMessage) = getAttributeFromPolicy(tppURL, apikey, policyDN, "Certificate Authority", "X509 Certificate", policyFailMessage)

    if (policyFailed) { println("ERROR : Certificate authority not set for the policy") }
    if (city == null) {
      println("ERROR : City not set for policy")
      policyFailed = true
    }
    if (state == null) {
      println("ERROR : State not set for policy")
      policyFailed = true
    }
    if (country == null) {
      println("ERROR : Country not set for policy")
      policyFailed = true
    }
    if (organization == null) {
      println("ERROR : Organization not set for policy")
      policyFailed = true
    }
    if (organizationalUnit == null) {
      println("ERROR : Organizational unit not set for policy")
      policyFailed = true
    }
    if (keyAlgorithm == null) {
      println("ERROR : Key algorithm not set for policy")
      policyFailed = true
    }
    if (managementType == null) {
      println("ERROR : Management type not set for policy")
      policyFailed = true
    }

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Policy values           ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("City                  : " + city)
    println("State                 : " + state)
    println("Country               : " + country)
    println("Organization          : " + organization)
    println("Organization unit     : " + organizationalUnit)
    println("Key algorithm         : " + keyAlgorithm)
    println("Key bit strength      : " + keyBitStrength)
    println("Management type       : " + managementType)
    println("Manual CSR            : " + manualCSR)
    println("Certificate authority : " + certificateAuthority)
    println("Policy DN             : " +  policyDN)

    // Get custom fields

    getCustomFields(tppURL, apikey)

    println("Custom Fields ........")
    for (def customFieldDefCounter = 0; customFieldDefCounter < customFields.getNumCustomFields(); customFieldDefCounter++) {
      println(customFields.getCustomFieldDef(customFieldDefCounter).getLabel())
    }

    if (!policyFailed) {
      // create policy communication string

      JSONObject jsonOutput = new JSONObject()
      jsonOutput.put("city", city)
      jsonOutput.put("state", state)
      jsonOutput.put("country", country)
      jsonOutput.put("organization", organization)
      jsonOutput.put("organizationalUnit", organizationalUnit)
      jsonOutput.put("keyAlgorithm", keyAlgorithm)
      jsonOutput.put("keyBitStrength", keyBitStrength)
      jsonOutput.put("managementType", managementType)
      jsonOutput.put("manualCSR", manualCSR)
      jsonOutput.put("certificateAuthority", certificateAuthority)
      jsonOutput.put("policyDN", policyDN)

      apTool.setOutputProperty("policy", jsonOutput.toString())
      apTool.setOutputProperty("certificateAuthority", certificateAuthority)
    } else {
      apTool.setOutputProperty("policy", "")
      apTool.setOutputProperty("certificateAuthority", "")
      println("=======================================")
      println("== Policy not retrieved              ==")
      println("=======================================")
    }
    apTool.setOutputProperties()

  }

  def getCustomFields(String tppURL, String apikey) {

    try {
      HashMap customFieldsMap = tpp.retrieveCustomFieldData(tppURL, apikey)

      JSONObject jsonCustomFields = new JSONObject(customFieldsMap)

      for (def itemCounter = 0; itemCounter < jsonCustomFields.Items.size(); itemCounter++) {
        String label = jsonCustomFields.Items[itemCounter].Label
        String guid = jsonCustomFields.Items[itemCounter].Guid
        String regularExpression = jsonCustomFields.Items[itemCounter].RegularExpression
        String defaultValue = jsonCustomFields.Items[itemCounter].DefaultValues

        if (guid.length() > 3) {
          guid = guid.substring(1, guid.length() - 1)
        }
        if (defaultValue == "[]") {
          defaultValue = ""
        }
        if (regularExpression == null) {
          regularExpression = ""
        }

        CustomField customFieldToAdd = new CustomField(label, guid, regularExpression, defaultValue)

        customFields.addCustomField(customFieldToAdd)

      }
    } catch (Exception e) {
      println("ERROR - getting custom fields")
      println(e)
      System.exit(-1)
    }
  }

  def requestCertificate() {
    def tppURL = props['tppURL'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()
    def policyDN = props['policyDN'].trim()
    def caDN = props['caDN'].trim()
    def certificateName = props['certificateName'].trim()
    def subjectAltNames = props['subjectAltNames'].trim()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Request certificate     ~~")
    println("~~ Parameters              ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL                    : " + tppURL)
    println("tppUser                   : " + tppUser)
    println("policyDN                  : " + policyDN)
    println("caDN                      : " + caDN)
    println("Certificate name          : " + certificateName)
    println("Subject alternative names : " + subjectAltNames)

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    String processedSubjectAlternativeNames = processSubjectAlternativeNames(subjectAltNames)

    try {
      def request = tpp.requestCertificate(tppURL, apikey, policyDN, caDN, certificateName, processedSubjectAlternativeNames)

      println "Certificate full name : " + request.CertificateDN

      apTool.setOutputProperty("certificateDN", request.CertificateDN)
      apTool.setOutputProperties()

    } catch (Exception e) {
      println("ERROR")
      println(e)
      System.exit(-1)
    }
  }

  def generateCertificateCSR() {
    def policyDetails = props['policyDetails'].trim()
    def certificateName = props['certificateName'].trim()
    def emailAddress = props['emailAddress'].trim()
    def websiteURL = props['websiteURL'].trim()
    def privateKeyFileName = props['privateKeyFileName'].trim()
    def publicKeyFileName = props['publicKeyFileName'].trim()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Generate certificate CSR ~~")
    println("~~ Parameters               ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("policyDetails        : " + policyDetails)
    println("Certificate name     : " + certificateName)
    println("Email Address        : " + emailAddress)
    println("Website URL          : " + websiteURL)
    println("Private key filename : " + privateKeyFileName)
    println("Public key filename  : " + publicKeyFileName)

    String city = ""
    String state = ""
    String country = ""
    String organization = ""
    String organizationalUnit = ""
    String keyBitStrength = ""
    Integer keyBitStrengthInt = 0
    String managementType = ""
    String manualCSR = ""
    String certificateAuthority = ""
    String keyAlgorithm = ""
    String policyDN

    def slurper = new JsonSlurper()
    def policyDetailsJSON = slurper.parseText(policyDetails)

    city = policyDetailsJSON.city
    state = policyDetailsJSON.state
    country = policyDetailsJSON.country
    organization = policyDetailsJSON.organization
    organizationalUnit = policyDetailsJSON.organizationalUnit
    keyAlgorithm = policyDetailsJSON.keyAlgorithm
    keyBitStrength = policyDetailsJSON.keyBitStrength
    if (keyBitStrength.length() > 0) {
      keyBitStrengthInt = keyBitStrength.toInteger()
    }
    managementType = policyDetailsJSON.managementType
    manualCSR = policyDetailsJSON.manualCSR
    certificateAuthority = policyDetailsJSON.certificateAuthority
    policyDN = policyDetailsJSON.policyDN

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Policy values           ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("City                  : " + city)
    println("State                 : " + state)
    println("Country               : " + country)
    println("Organization          : " + organization)
    println("Organization unit     : " + organizationalUnit)
    println("Key algorithm         : " + keyAlgorithm)
    println("Key bit strength      : " + keyBitStrength)
    println("Management type       : " + managementType)
    println("Manual CSR            : " + manualCSR)
    println("Certificate authority : " + certificateAuthority)
    println("Policy DN             : " + policyDN)


    CSR myCSR = new CSR(keyAlgorithm, keyBitStrengthInt, "SHA1withRSA")

    myCSR.setCertificateCountry(country)
    myCSR.setCertificateState(state)
    myCSR.setCertificateCity(city)
    myCSR.setCertificateOrganization(organization)
    myCSR.setCertificateOrganizationUnit(organizationalUnit)
    myCSR.setCertificateWebSiteURL(websiteURL)
    myCSR.setCertificateEmailAddress(emailAddress)

    String csr = myCSR.getCSR()

    // Get private and public keys

    myCSR.getPrivateKey(privateKeyFileName)
    myCSR.getPublicKey(publicKeyFileName)

    apTool.setOutputProperty("policyDN", policyDN)
    apTool.setOutputProperty("csr", csr)
    apTool.setOutputProperty("certificateAuthority", certificateAuthority)
    apTool.setOutputProperty("certificateName", certificateName)
    apTool.setOutputProperty("privateKeyFile", privateKeyFileName)
    apTool.setOutputProperty("publicKeyFile", privateKeyFileName)
    apTool.setOutputProperties()

  }

  def submitCSRToVenafiServer() {
    def tppURL = props['tppURL'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()
    def policyDN = props['policyDN'].trim()
    def csrText = props['csrText'].trim()
    def csrFile = props['csrFile'].trim()
    def caDN = props['caDN'].trim()
    def certificateName = props['certificateName'].trim()
    def subjectAltNames = props['subjectAltNames'].trim()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Submit CSR to Venafi Server ~~")
    println("~~ Parameters                  ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL                    : " + tppURL)
    println("tppUser                   : " + tppUser)
    println("policyDN                  : " + policyDN)
    println("Certificate authority     : " + caDN)
    println("Subject alternative names : " + subjectAltNames)
    println("Certificate name          : " + certificateName)
    println("CSR text file             : " + csrFile)

    String processedSubjectAlternativeNames = processSubjectAlternativeNames(subjectAltNames)

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    if ((csrText.length() == 0) && (csrFile.length() == 0)) {
      println("ERROR : CSR missing ...")
      println("CSR content must be supplied either as a block of CSR text in the 'CSR Text' field or")
      println("a name of a file that contains the CSR text must be entered in the 'CSR File' field.")
      return
    }

    def fileObject = null

    if (csrText.length() == 0) {
      // Get CSR content from the file

      if (csrFile.length() > 0) {

        def workDir = new File('.').canonicalFile
        File csrFileObject = new File(workDir, csrFile)

        if (csrFileObject.isFile()) {
          csrText = csrFileObject.getText()

        } else {
          println("ERROR : CSR file does not exist. CSR will not be submitted")
          return
        }
      }
    }
    try {
      def requestCSR = tpp.submitCertificateCSR(tppURL, apikey, policyDN, csrText, caDN, certificateName, processedSubjectAlternativeNames)

      println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
      println("~~ Certificate generated   ~~")
      println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
      println("Certificate DN : " + requestCSR.CertificateDN)

      apTool.setOutputProperty("certificateDN", requestCSR.CertificateDN)
      apTool.setOutputProperties()

    } catch (Exception e) {
      println("ERROR")
      println(e)
      System.exit(-1)
    }
  }

  String processSubjectAlternativeNames(String subjectAltNames) {

    String processedSubjectAltName = ""

    if (subjectAltNames.length() > 0) {

      processedSubjectAltName = "["

      def splitItems = subjectAltNames.split(";")

      println("Subject alternative names ...")
      splitItems.each { item ->
        def splitItem = item.split(":")
        def subjectAltNameType = splitItem[0].trim()
        def subjectAltName = splitItem[1].trim()
        if (splitItem.size() != 2) {
          println("Error : subject alternative name constructed wrong. Should be in the format of 'type: value' such as '2: www.ibm.com'")
        } else {
          if ((subjectAltNameType == "OtherName") || (subjectAltNameType == "Email") || (subjectAltNameType == "DNS") || (subjectAltNameType == "URI") || (subjectAltNameType == "IPAddress")) {
            if (processedSubjectAltName.length() > 1) {
              processedSubjectAltName += ","
            }
            processedSubjectAltName += " { \"TypeName\": \"" + subjectAltNameType + "\", \"Name\": \"" + subjectAltName + "\" }"
            println("\t" + subjectAltNameType + " : " + subjectAltName)
          } else {
            println("Error : undefined subject alternative name type : " + subjectAltNameType)
            println("Subject alternative name NOT added : " + subjectAltName)
          }
        }
      }
      processedSubjectAltName += " ]"
    }

    return(processedSubjectAltName)
  }

  def submitCustomFieldsToVenafiServer() {
    def tppURL = props['tppURL'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()
    def certificateDN = props['certificateDN'].trim()
    def customFieldValues = props['customFields'].trim()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Submit custom fields to Venafi server  ~~")
    println("~~ Parameters                             ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL                  : " + tppURL)
    println("tppUser                 : " + tppUser)
    println("Certificate DN          : " + certificateDN)
    println("Custom fields & values  : " + customFieldValues)

    String customFieldDataForVenafi = ""

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    getCustomFields(tppURL, apikey)

    def splitCustomFields = customFieldValues.split(";")

    splitCustomFields.each {
      def field = it.split(":")
      field[0] = field[0].trim()
      field[1] = field[1].trim()

      // Find the entry in the customFields object and get the GUID

      for (def customFieldDefCounter = 0; customFieldDefCounter < customFields.getNumCustomFields(); customFieldDefCounter++) {
        if (customFields.getCustomFieldDef(customFieldDefCounter).getLabel() == field[0]) {
          if (customFieldDataForVenafi.length() > 0) {
            customFieldDataForVenafi += ",\n"
          }
          customFieldDataForVenafi += "{ \"ItemGuid\": \"{" + customFields.getCustomFieldDef(customFieldDefCounter).getGUID() + "}\""
          customFieldDataForVenafi += ", \"List\": [\""+ field[1] + "\"]}"
        }
      }
    }
    customFieldDataForVenafi = "[ " + customFieldDataForVenafi + " ]"

    try {
      def request = tpp.sendCustomFieldsToVenafiServer(tppURL, apikey, certificateDN, customFieldDataForVenafi)

      apTool.setOutputProperties()

    } catch (Exception e) {
      println("ERROR")
      println(e)
      System.exit(-1)
    }
  }


  def getAttributeFromPolicy(def tppURL, def apikey, def policyDN, def attribute, def className, String policyFailMessage) {
    def requestAttributeResponse = tpp.readPolicyValue(tppURL, apikey, policyDN, attribute, className)
    String response = ""
    Boolean policyFailed = false

    if (requestAttributeResponse.containsKey("Result")) {
      if (requestAttributeResponse.Result == 1) {
        if (requestAttributeResponse.containsKey("Values")) {
          if (requestAttributeResponse.Values.size() > 0) {
            response = requestAttributeResponse.Values[0]
          }
        }
      }
    }
    if (response.length() == 0) {
      policyFailed = true
      policyFailMessage += attribute
    }
    return [response, policyFailed, policyFailMessage]
  }

  def checkPolicy(def tppURL, def apikey, def policyDN) {
    def requestAttributeResponse = tpp.checkPolicy(tppURL, apikey, policyDN)

    return(requestAttributeResponse)

  }

  def requestCertificateWait() {

    def tppURL = props['tppURL'].trim()
    def policyDN = props['policyDN'].trim()
    def caDN = props['caDN'].trim()
    def certificateName = props['certificateName'].trim()
    def format = props['format'].trim()
    def includeChain = props['includeChain'].trim()
    def includePrivateKey = props['includePrivateKey'].trim()
    def friendlyName = props['friendlyName'].trim()
    def keystorePassword = props['keystorePassword'].trim()
    def privateKeyProtectionPassword = props['privateKeyProtectionPassword'].trim()
    def requestedFilename = props['filename'].trim()
    def timeout = props['timeout'].trim()
    def interval = props['interval'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()
    def subjectAltNames = props['subjectAltNames'].trim()

    if (includePrivateKey == "") {
      includePrivateKey = "false"
    }
    if (includeChain == "") {
      includeChain = "false"
    }

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Request certificate (wait) ~~")
    println("~~ Parameters                 ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL                    : " + tppURL)
    println("tppUser                   : " + tppUser)
    println("policyDN                  : " + policyDN)
    println("caDN                      : " + caDN)
    println("certificate name          : " + certificateName)
    println("format                    : " + format)
    println("includeChain              : " + includeChain)
    println("includePrivateKey         : " + includePrivateKey)
    println("Private key Protection pw : " + privateKeyProtectionPassword)
    println("Friendly name             : " + friendlyName)
    println("Keystore password         : " + keystorePassword)
    println("Filename                  : " + requestedFilename)
    println("Timeout                   : " + timeout)
    println("Interval                  : " + interval)
    println("Subject alternative names : " + subjectAltNames)

    if (analyseCertificateRequestOptions(format, includeChain, keystorePassword, includePrivateKey, privateKeyProtectionPassword, friendlyName, keystorePassword)) {
      return
    }

    if (((format == "Base64") || (format == "DER") || (format == "PKCS #7")) && (includePrivateKey == "true")) {
        includePrivateKey = "false"
    }

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    String processedSubjectAlternativeNames = processSubjectAlternativeNames(subjectAltNames)

    // 1. Request the certificate and store the certificateDN and wait
    def request = null
    try {
      println("requesting certificate : ")
      request = tpp.requestCertificate(tppURL, apikey, policyDN, caDN, certificateName, processedSubjectAlternativeNames)
    } catch(Exception e) {
      println("ERROR ... 1")
      println(e)
      System.exit(-1)
    }

    def certificateDNFromRequest = request.CertificateDN

    apTool.setOutputProperty("certificateDN", request.CertificateDN)
    apTool.setOutputProperty("Certificate Name", certificateName)

    getCertificate("getCertificateWait", tppURL, apikey, certificateDNFromRequest, format, includeChain, includePrivateKey, privateKeyProtectionPassword, friendlyName, keystorePassword, requestedFilename, timeout, interval)
  }

  def retrieveCertificate() {
    def tppURL = props['tppURL'].trim()
    def certificateDN = props['certificateDN'].trim()
    def format = props['format'].trim()
    def includeChain = props['includeChain'].trim()
    def includePrivateKey = props['includePrivateKey'].trim()
    def friendlyName = props['friendlyName'].trim()
    def keystorePassword = props['keystorePassword'].trim()
    def privateKeyProtectionPassword = props['privateKeyProtectionPassword'].trim()
    def requestedFilename = props['filename'].trim()
    def timeout = props['timeout'].trim()
    def interval = props['interval'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()

    if (includePrivateKey == "") {
      includePrivateKey = "false"
    }
    if (includeChain == "") {
      includeChain = "false"
    }

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Retrieve certificate    ~~")
    println("~~ Parameters              ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL                    : " + tppURL)
    println("tppUser                   : " + tppUser)
    println("certificateDN             : " + certificateDN)
    println("format                    : " + format)
    println("includeChain              : " + includeChain)
    println("includePrivateKey         : " + includePrivateKey)
    println("Private key Protection pw : " + privateKeyProtectionPassword)
    println("Friendly name             : " + friendlyName)
    println("Keystore password         : " + keystorePassword)
    println("Filename                  : " + requestedFilename)
    println("Timeout                   : " + timeout)
    println("Interval                  : " + interval)

    // Analyse the options and report any misalignment

    if (analyseCertificateRequestOptions(format, includeChain, keystorePassword, includePrivateKey, privateKeyProtectionPassword, friendlyName, keystorePassword)) {
      apTool.setOutputProperty("Status", "Failure")
      apTool.setOutputProperties()

      return
    }

    if (((format == "Base64") || (format == "DER") || (format == "PKCS #7")) && (includePrivateKey == "true")) {
        includePrivateKey = "false"
    }

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    getCertificate("retrieveCertificate", tppURL, apikey, certificateDN, format, includeChain, includePrivateKey, privateKeyProtectionPassword, friendlyName, keystorePassword, requestedFilename, timeout, interval)

  }

  // Private function used by 'getCertificateWait' and 'retrieveCertificate'

  private getCertificate(String type, String tppURL, String apikey, String certificateDN, String format, String includeChain, String includePrivateKey, String privateKeyProtectionPassword, String friendlyName, String keystorePassword, String requestedFilename, String timeout, String interval) {
    def meta = null
    Integer waitForInt = interval.isInteger() ? interval.toInteger() : 10

    if (type == "getCertificateWait") {
      println "Waiting for Venafi TPP " + interval + " Seconds...."
      Thread.sleep(waitForInt * 1000)
    }

    try {
      meta = tpp.certificateMeta(tppURL, apikey, certificateDN)
    } catch (Exception e) {
      println("ERROR ... 1")
      println(e)
      System.exit(-1)
    }

    Date currentDateTime = new Date()
    Date endDateTime = new Date()

    use(TimeCategory) {
      endDateTime = currentDateTime + (timeout.toInteger()).seconds
    }

    currentDateTime = new Date()
    boolean firstPass = true

    while ((currentDateTime < endDateTime) && (meta.ProcessingDetails.size() > 0)) {
      if (firstPass) {
        print("Polling for certificate status ")
        firstPass = false
      } else {
        print(".")
      }

      Thread.sleep(interval.toInteger() * 1000)
      currentDateTime = new Date()
      try {
        meta = tpp.certificateMeta(tppURL, apikey, certificateDN)
      } catch (Exception e) {
        println("ERROR ... 2")
        System.exit(-1)
      }
    }
    println("")

    if (type == "getCertificateWait") {
      Thread.sleep(waitForInt * 1000)
    }

    if (meta.ProcessingDetails.Status || meta.ProcessingDetails.Stage ) {
      apTool.setOutputProperty("Ready", 'false')
      apTool.setOutputProperty("processingStatus", meta.ProcessingDetails.Status)
      apTool.setOutputProperty("processingStage",  String.valueOf(meta.ProcessingDetails.Stage))
      apTool.setOutputProperty("tppTicketDN",  String.valueOf(meta.ProcessingDetails.TicketDN))
      apTool.setOutputProperty("filename", "")
      apTool.setOutputProperty("Status", "Failure")
      apTool.setOutputProperties()
    } else {

      println "Certificate Ready"

      def retrieve = null
      try {
        retrieve = tpp.retrieveCertificate(tppURL, apikey, certificateDN, format, includeChain, includePrivateKey, privateKeyProtectionPassword, friendlyName, keystorePassword)
      } catch (Exception e) {
        println("ERROR ... 3")
        println(e)
        System.exit(-1)
      }

      def certificateData = retrieve.toString()
      def fileName = ""

      if (format == "Base64") {
        fileName = writeBase64EncodedCertToFile(requestedFilename, certificateData, "base64")
      } else if (format == "PKCS #7") {
        fileName = writeBase64EncodedCertToFile(requestedFilename, certificateData, "p7b")
      } else if (format == "PKCS #12") {
        fileName = writeBase64EncodedCertToFile(requestedFilename, certificateData, "p12")
      } else if (format == "DER") {
        fileName = writeBase64EncodedCertToFile(requestedFilename, certificateData, "DER")
      } else if (format == "JKS") {
        fileName = writeBase64EncodedCertToFile(requestedFilename, certificateData, "JKS")
      }

      println("Certificate file stored in : " + fileName)

      apTool.setOutputProperty("filename", fileName)
      apTool.setOutputProperty("Ready", 'true')
      apTool.setOutputProperty("approverGUID", meta.Approver[0])
      apTool.setOutputProperty("approverDN", tpp.guidToDN(tppURL, apikey, meta.Approver[0].minus("local:")).ObjectDN)
      apTool.setOutputProperty("contactGUID", meta.Contact[0])
      apTool.setOutputProperty("contactDN", tpp.guidToDN(tppURL, apikey, meta.Contact[0].minus("local:")).ObjectDN)
      apTool.setOutputProperty("Status", "Success")
      apTool.setOutputProperties()
    }
  }

  Boolean analyseCertificateRequestOptions(String format, String includeChain, String KeyStorePassword, String includePrivateKey, String privateKeyProtectionPassword, String friendlyName, String keystorePassword) {

    Boolean returnValue = false

    if (format == "Base64") {
      if (keystorePassword.length() != 0) {
        println("Keystore password given as an argument will be ignored for a base64 certificate")
      }
      if (includePrivateKey == "true") {
        println("Base64 certificates do not protect the private key so the private key will not be included.")
      }
      if (privateKeyProtectionPassword.length() != 0) {
        println("Private key protection password given, but private key will not be included. Password ignored.")
      }
    } else if (format == "PKCS #7") {
      if (includePrivateKey == "true") {
        println("Private key requested but not available for a PKCS#7 certificate")
      }
      if (friendlyName.length() != 0) {
        println("Friendly name given as an argument will be ignored for a PKCS #7 certificate")
      }
      if (keystorePassword.length() != 0) {
        println("Keystore password given as an argument will be ignored for a PKCS #7 certificate")
      }
    }
    else if (format == "PKCS #12") {
      if (friendlyName.length() != 0) {
        println("Friendly name given as an argument will be ignored for a PKCS #12 certificate")
      }
      if (keystorePassword.length() != 0) {
        println("Keystore password given as an argument will be ignored for a PKCS #12 certificate")
      }
    } else if (format == "DER") {
      if (includePrivateKey == "true") {
        println("Private key requested but not available for a DER certificate")
      }
      if (includeChain == "true") {
        println("Certificate chain requested but not available for a DER certificate")
      }
      if (friendlyName.length() != 0) {
        println("Friendly name given as an argument will be ignored for DER certificate")
      }
      if (keystorePassword.length() != 0) {
        println("Keystore password given as an argument will be ignored for a DER certificate")
      }

    } else if (format == "JKS") {
      if (keystorePassword.length() == 0) {
        println("Keystore password must be given")
        println("=======================================")
        println("== Certificate will not be retrieved ==")
        println("=======================================")
        return true
      }
      if ((privateKeyProtectionPassword.length() == 0) && (includePrivateKey == "true")) {
        println("Private key requested but private key protection password not given.")
        println("To include the private key it must be protected with a password.")
        println("=======================================")
        println("== Certificate will not be retrieved ==")
        println("=======================================")
        return true
      }
    }
  }


  def getCertificateStatus() {
    def tppURL = props['tppURL'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()
    def certificateDN = props['certificateDN'].trim()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Get certificate status  ~~")
    println("~~ Parameters              ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL        " + tppURL)
    println("tppUser       " + tppUser)
    println("certificateDN " + certificateDN)

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    try {
      def meta = tpp.certificateMeta(tppURL, apikey, certificateDN)

      println("meta.ProcessingDetails size : " + meta.ProcessingDetails.size())

      if (meta.ProcessingDetails.size() > 0) {
        println("Processing status : " + meta.ProcessingDetails.Status)
        apTool.setOutputProperty("Ready", 'false')
        apTool.setOutputProperty("processingStatus", meta.ProcessingDetails.Status)
        apTool.setOutputProperties()
      }
      else {
        apTool.setOutputProperty("Ready", 'true')
        apTool.setOutputProperty("processingStatus", "N/A")
        apTool.setOutputProperty("processingStage", "N/A")

        Date validFromDate = Date.parse("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", meta.CertificateDetails.ValidFrom)
        Date validToDate = Date.parse("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", meta.CertificateDetails.ValidTo)
        println("From  : " + validFromDate.format("dd MMMM yyyy") + " to : " + validToDate.format("dd MMMM yyyy"))

        Date currentDate = new Date()

        def daysValidFor = validToDate.minus(validFromDate)
        def daysRemaining = validToDate.minus(currentDate)

        apTool.setOutputProperty("approverGUID", meta.Approver[0])
        apTool.setOutputProperty("approverDN", tpp.guidToDN(tppURL, apikey, meta.Approver[0].minus("local:")).ObjectDN)
        apTool.setOutputProperty("contactGUID", meta.Contact[0])
        apTool.setOutputProperty("contactDN", tpp.guidToDN(tppURL, apikey, meta.Contact[0].minus("local:")).ObjectDN)
        apTool.setOutputProperty("signatureAlgorithm", meta.CertificateDetails.SignatureAlgorithm)
        apTool.setOutputProperty("validFrom", meta.CertificateDetails.ValidFrom)
        apTool.setOutputProperty("validTo", meta.CertificateDetails.ValidTo)
        apTool.setOutputProperty("keySize", sprintf("%d", meta.CertificateDetails.KeySize))
        apTool.setOutputProperty("validFor", daysValidFor.toString())
        apTool.setOutputProperty("daysRemaining", daysRemaining.toString())
        apTool.setOutputProperties()

        if (daysValidFor < 0) {
          println("Error!!!")
          println("'Valid to' date is before the 'valid from' date")
        } else {
          println("Valid for " + daysValidFor + " days.")
        }

        if (daysRemaining < 0) {
          println("Certificate expired " + (daysRemaining * -1) + " days ago")
        } else {
          println(daysRemaining + " days remaining.")
        }
        println("====================================================")
        println("Approver GUID       : " + meta.Approver[0])
        println("Approver DN         : " + tpp.guidToDN(tppURL, apikey, meta.Approver[0].minus("local:")).ObjectDN)
        println("Contact GUID        : " + meta.Contact[0])
        println("Contact DN          : " + tpp.guidToDN(tppURL, apikey, meta.Contact[0].minus("local:")).ObjectDN)
        println("Signature algorithm : " + meta.CertificateDetails.SignatureAlgorithm)
        println("Valid from          : " + meta.CertificateDetails.ValidFrom)
        println("Valid to            : " + meta.CertificateDetails.ValidTo)
        println("Key size            : " + sprintf("%d", meta.CertificateDetails.KeySize))
        println("Valid for (days)    : " + daysValidFor)
        println("Days remaining      : " + daysRemaining)
      }
    }  catch (Exception e) {
      println("ERROR")
      println(e)
      System.exit(-1)
    }
  }

  def validateRemainingDays() {
    def tppURL = props['tppURL'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()
    def certificateDN = props['certificateDN'].trim()
    def failIflessThan = props['failIfLessThan'].trim()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Validate remaining days ~~")
    println("~~ Parameters              ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL                        : " + tppURL)
    println("tppUser                       : " + tppUser)
    println("certificateDN                 : " + certificateDN)
    println("Required outstanding validity : " + failIflessThan)

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    try {
      def meta = tpp.certificateMeta(tppURL, apikey, certificateDN)

      if (meta.ProcessingDetails.Status) {
        apTool.setOutputProperty("Ready", 'false')
        apTool.setOutputProperty("processingStatus", meta.ProcessingDetails.Status)
        apTool.setOutputProperty("processingStage",  String.valueOf(meta.ProcessingDetails.Stage))
      }
      else {
        apTool.setOutputProperty("Ready", 'true')
        apTool.setOutputProperty("processingStatus", "N/A")
        apTool.setOutputProperty("processingStage", "N/A")
      }

      Date validFromDate = Date.parse("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", meta.CertificateDetails.ValidFrom)
      Date validToDate = Date.parse("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", meta.CertificateDetails.ValidTo)
      println("From  : " + validFromDate.format("dd MMMM yyyy") + " to : " + validToDate.format("dd MMMM yyyy"))

      Date currentDate = new Date()

      def daysValidFor = validToDate.minus(validFromDate)
      def daysRemaining = validToDate.minus(currentDate)

      apTool.setOutputProperty("validFor", daysValidFor.toString())
      apTool.setOutputProperty("daysRemaining", daysRemaining.toString())

      if (daysValidFor < 0) {
        println("Error!!!")
        println("'Valid to' date is before the 'valid from' date")
      } else {
        println("Valid for " + daysValidFor + " days.")
      }

      println("Certificate days remaining : " + daysRemaining)
      if (daysRemaining.toInteger() < failIflessThan.toInteger()) {
        println("Certificate fails validation")
        apTool.setOutputProperty("CertificateOK", "false")
      } else {
        println("Certificate passes validation")
        apTool.setOutputProperty("CertificateOK", "true")
      }
    } catch (Exception e) {
      println("ERROR")
      System.exit(-1)
    }
    apTool.setOutputProperties()
    System.exit(0)
  }

  def revokeCertificate() {
    def tppURL = props['tppURL'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()
    def certificateDN = props['certificateDN'].trim()
    def reasonCode = props['reasonCode'].trim()
    def commentText = props['comment'].trim()
    def disabled = props['disabled'].trim()

    if (disabled != null) {
      if (disabled != "true") {
        disabled = "false"
      }
    }

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Revoke certificate      ~~")
    println("~~ Parameters              ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    println("tppURL        : " + tppURL)
    println("tppUser       : " + tppUser)
    println("certificateDN : " + certificateDN)
    if (commentText != null) {
      println("Comment text  : " + commentText)
    }
    println("Disabled      : " + disabled)
    print("Reason code   : " + reasonCode + "  ")
    if (reasonCode == "0") {
      println("none")
    } else if (reasonCode == "1") {
      println("User key compromised")
    } else if (reasonCode == "2") {
      println("CA key compromised")
    } else if (reasonCode == "3") {
      println("User changed affiliation")
    } else if (reasonCode == "4") {
      println("Certificate superseded")
    } else if (reasonCode == "5") {
      println("Original use no longer valid")
    } else {
      println("Error : reason code invalid")
    }

    def exitCode = 0

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    try {
      def request = tpp.revokeCertificate(tppURL, apikey, certificateDN, reasonCode, commentText, disabled)
      if (request.Revoked) {
        println("Revoke status : " + request.Revoked)
      }
      if (request.Requested) {
        println("Request status : " + request.Requested)
      }
      if (request.Success) {
        println("Success status : " + request.Success)
        apTool.setOutputProperty("RevokeStatus", request.Success.toString())
        if (request.Success != true) {
          exitCode = -1
        }
      }
    } catch (Exception e) {
      println("ERROR")
      exitCode = -1
      apTool.setOutputProperty("RevokeStatus", "false")
    }

    apTool.setOutputProperties()
    System.exit(exitCode)
  }

  def renewCertificate() {
    def tppURL = props['tppURL'].trim()
    def tppUser = props['tppUser'].trim()
    def tppPassword = props['tppPassword'].trim()
    def certificateDN = props['certificateDN'].trim()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Renew certificate       ~~")
    println("~~ Parameters              ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("tppURL        : " + tppURL)
    println("tppUser       : " + tppUser)
    println("certificateDN : " + certificateDN)

    def exitCode = 0

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    try {
      def request = tpp.renewCertificate(tppURL, apikey, certificateDN)

      if (request.Error) {
        println("Renew error : " + request.Error)
        apTool.setOutputProperty("RenewalError", request.Error)
      }
      if (request.Success) {
        println("Success status : " + request.Success)
        apTool.setOutputProperty("RenewalStatus", request.Success.toString())
        if (request.Success != true) {
          exitCode = -1
        }
      }
    } catch (Exception e) {
      println("ERROR")
      exitCode = -1
      apTool.setOutputProperty("RenewalStatus", "false")
    }
    apTool.setOutputProperties()

    System.exit(exitCode)
  }

  private String writeBase64EncodedCertToFile(String filename, String certificateData, String extension) {

    def searchTermForCertificateData=""

    if (certificateData.contains("[")) {
      searchTermForCertificateData = "CertificateData:"
    } else {
      searchTermForCertificateData = "CertificateData="
    }
    certificateData = certificateData.substring(1, certificateData.length())
    certificateData = certificateData.substring(0, certificateData.length() - 1)

    certificateData = certificateData.replaceAll("\\s","")

    def splitCertificate = certificateData.split(",")

    if (splitCertificate.size() > 0) {
      def certFound = 0
      def elementCounter = 0
      while ((certFound == 0) && (elementCounter < splitCertificate.size())) {
        if (splitCertificate[elementCounter].contains(searchTermForCertificateData)) {
          certFound = 1
          //def certificate = splitCertificate[elementCounter].substring(searchTermForCertificateData.length() + 1, splitCertificate[elementCounter].length())
          def certificate = splitCertificate[elementCounter].replaceAll(searchTermForCertificateData,"")
          if (certificate.length() > 0) {
            // write the certificate to a file on the host

            byte[] decoded = certificate.decodeBase64()
            def decodedCertificate = new String(decoded)

            def splitLinesCert = decodedCertificate.split("\n")
            filename = filename + "." + extension
            new File(filename).bytes = certificate.decodeBase64()

          } else {
            println("Problem with the returned certificate data - CertificateData found but empty")
            println(certificateData)
          }
        }
        elementCounter++
      }
      if (certFound == 0) {
        println("Problem with the returned certificate data - unable to find the section " + searchTermForCertificateData)
        println(certificateData)
      }
    } else {
      println("Problem with the returned certificate data - certificate doesn't have sections")
      println(certificateData)
    }
    return filename
}
}
