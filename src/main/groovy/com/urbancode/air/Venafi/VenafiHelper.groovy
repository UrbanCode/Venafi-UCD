/*
 * Licensed Materials - Property of IBM Corp.
 * IBM UrbanCode Deploy
 * (c) Copyright IBM Corporation 2011, 2014. All Rights Reserved.
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

import org.codehaus.jettison.json.JSONObject
import org.codehaus.jettison.json.JSONArray
import groovy.json.JsonSlurper

import com.urbancode.air.AirPluginTool
import com.urbancode.ud.client.AgentClient
import com.urbancode.ud.client.ResourceClient
import com.urbancode.ud.client.EnvironmentClient
import com.urbancode.commons.util.FileFilterToRegex

import com.urbancode.air.httpRequestProcess
import com.urbancode.air.UCDServerConnection

import org.apache.http.HttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.DefaultHttpClient

import com.urbancode.commons.httpcomponentsutil.HttpClientBuilder

import com.urbancode.air.Venafi.VenafiRESTAPI

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

  private boolean validateUrbanCodeAgentForExecution() {
    def httpProcess = new httpRequestProcess(serverConnection, true)

    httpProcess.httpGetSystemProperties()


  }

  def authenticate() {
    def tppURL = props['tppurl']
    def tppUser = props['tppUser']
    def tppPassword = props['tppPassword']

    println("Parameters ")
    println("tppURL      " + tppURL)
    println("tppUser     " + tppUser)
    println("tppPassword " + tppPassword)

    //def request = tpp.authenticate(tppURL, tppUser, tppPassword)
    //println request

    //apTool.setOutputProperty("APIKey", request.APIKey)
    //apTool.setOutputProperties()

    validateUrbanCodeAgentForExecution()
  }

  def requestCertificate() {
    def tppURL = props['tppurl']
    def tppUser = props['tppUser']
    def tppPassword = props['tppPassword']
    def policyDn = props['policyDn']
    def caDn = props['caDn']
    def x509Subject = props['x509Subject']

    println("Parameters ")
    println("tppURL      " + tppURL)
    println("policyDn    " + policyDn)
    println("caDn        " + caDn)
    println("x509Subject " + x509Subject)
    println("tppUser     " + tppUser)
    println("tppPassword " + tppPassword)

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    try {
      def request = tpp.requestCertificate(tppURL, apikey, policyDn, caDn, x509Subject)

      println request

      apTool.setOutputProperty("certificateDN", request.CertificateDN)
      apTool.setOutputProperty("x509Subject", x509Subject)
      apTool.setOutputProperties()

    } catch (Exception e) {
      println("ERROR")
      System.exit(-1)
    }

  }

  def requestCertificateCSR() {
    def tppURL = props['tppurl']
    def tppUser = props['tppUser']
    def tppPassword = props['tppPassword']
    def cSRFile = props['CSRFile']
    def policyDn = props['policyDn']

    println("Parameters ")
    println("tppURL      " + tppURL)
    println("tppUser     " + tppUser)
    println("tppPassword " + tppPassword)
    println("CSRFile     " + cSRFile)
    println("policyDn    " + policyDn)

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    def request = tpp.readPolicyValue(tppURL, apikey, "\\VED\\Policy\\DevOps_Workshop", "Approver", "JKS")

    println(request)


    println("===========================================================================")

    /*
    String csr = new File(cSRFile).text

    println(apikey)

    println(csr)

    try {
      def request = tpp.requestCertificateCSR(tppURL, apikey, policyDn, csr)

      println request

      // apTool.setOutputProperty("certificateDN", request.CertificateDN)
      // apTool.setOutputProperty("x509Subject", x509Subject)
      // apTool.setOutputProperties()

    } catch (Exception e) {
      println("ERROR")
      System.exit(-1)
    } */

  }

  def retrieveCertificate() {
    def tppURL = props['tppurl']
    def tppUser = props['tppUser']
    def tppPassword = props['tppPassword']
    def certificateDN = props['certificateDN']
    def Format = props['Format']
    def IncludeChain = props['IncludeChain']
    def IncludePrivateKey = props['IncludePrivateKey']
    def p12Password = props['p12Password']
    def requestedFilename = props['Filename']

    if (IncludePrivateKey == "") {
      IncludePrivateKey = "false"
    }
    if (IncludeChain == "") {
      IncludeChain = "false"
    }

    println("Parameters ")
    println("tppURL            " + tppURL)
    println("tppUser           " + tppUser)
    println("tppPassword       " + tppPassword)
    println("certificateDN     " + certificateDN)
    println("Format            " + Format)
    println("IncludeChain      " + IncludeChain)
    println("IncludePrivateKey " + IncludePrivateKey)
    println("p12Password       " + p12Password)
    println("Filename          " + requestedFilename)

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    def meta = null
    try {
      meta = tpp.certificateMeta(tppURL, apikey, certificateDN)
    } catch (Exception e) {
      println("ERROR ... 1")
      System.exit(-1)
    }

    if (meta.ProcessingDetails.Status || meta.ProcessingDetails.Stage ) {
      apTool.setOutputProperty("Ready", 'false')
      apTool.setOutputProperty("processingStatus", meta.ProcessingDetails.Status)
      apTool.setOutputProperty("processingStage",  String.valueOf(meta.ProcessingDetails.Stage))
      apTool.setOutputProperty("tppTicketDN",  String.valueOf(meta.ProcessingDetails.TicketDN))
      apTool.setOutputProperty("Filename", "")
      apTool.setOutputProperties()
    } else {
      println "Certificate Ready"

      def retrieve = null
      try {
        retrieve = tpp.retrieveCertificate(tppURL, apikey, certificateDN, Format, IncludeChain, IncludePrivateKey, p12Password)
      } catch (Exception e) {
        println("ERROR ... 2")
        System.exit(-1)
      }

      def certificateData = retrieve.toString()
      def fileName = ""

      if (Format == "PKCS #12") {
        fileName = writeBase64EncodedCertToFile(requestedFilename, certificateData, "p12")
      }
      println("Certificate file stored in : " + fileName)

      apTool.setOutputProperty("Filename", fileName)
      apTool.setOutputProperty("Ready", 'true')
      apTool.setOutputProperty("processingStatus", "N/A")
      apTool.setOutputProperty("processingStage", "N/A")
      apTool.setOutputProperty("approverGUID", meta.Approver[0])
      apTool.setOutputProperty("approverDN", tpp.guidToDN(tppURL, apikey, meta.Approver[0].minus("local:")).ObjectDN)
      apTool.setOutputProperty("contactGUID", meta.Contact[0])
      apTool.setOutputProperty("contactDN", tpp.guidToDN(tppURL, apikey, meta.Contact[0].minus("local:")).ObjectDN)
      apTool.setOutputProperties()
    }
  }

  def requestCertificateWait() {
    def tppURL = props['tppurl']
    def tppUser = props['tppUser']
    def tppPassword = props['tppPassword']
    def policyDn = props['policyDn']
    def caDn = props['caDn']
    def x509Subject = props['x509Subject']
    def waitFor = props["waitFor"]
    def tryTimes = props["tryTimes"]
    def Format = props['Format']
    def IncludeChain = props['IncludeChain']
    def IncludePrivateKey = props['IncludePrivateKey']
    def p12Password = props['p12Password']

    if (IncludePrivateKey == "") {
      IncludePrivateKey = "false"
    }
    if (IncludeChain == "") {
      IncludeChain = "false"
    }

    println("Parameters ")
    println("tppURL            " + tppURL)
    println("tppUser           " + tppUser)
    println("tppPassword       " + tppPassword)
    println("policyDn          " + policyDn)
    println("caDn              " + caDn)
    println("x509Subject       " + x509Subject)
    println("waitFor           " + waitFor)
    println("tryTimes          " + tryTimes)
    println("Format            " + Format)
    println("IncludeChain      " + IncludeChain)
    println("IncludePrivateKey " + IncludePrivateKey)
    println("p12Password       " + p12Password)


    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    // 1. Request the certificate and store the certificateDN and wait
    def request = null
    try {
      request = tpp.requestCertificate(tppURL, apikey, policyDn, caDn, x509Subject)
    } catch(Exception e) {
      println("ERROR ... 1")
      println(e)
      System.exit(-1)
    }
    println request
    def certificateDN = request.CertificateDN

    apTool.setOutputProperty("certificateDN", request.CertificateDN)
    apTool.setOutputProperty("x509Subject", x509Subject)

    println "Waiting for Venafi TPP " + waitFor + " Seconds...."
    Integer waitForInt = waitFor.isInteger() ? waitFor.toInteger() : 10
    Thread.sleep(waitForInt * 1000);

    // 2. Loop for certificate status

    Integer tryTimesInt = tryTimes.isInteger() ? tryTimes.toInteger() : 10

    def certificateReady = false

    for (int i = 0; i <tryTimesInt; i++) {
      def counter = i + 1;
      println "Attempt #" + counter

      def meta = tpp.certificateMeta(tppURL, apikey, certificateDN)

      //println JsonOutput.toJson(meta)
      if (meta.ProcessingDetails.Status || meta.ProcessingDetails.Stage ) {
        println JsonOutput.toJson(meta.ProcessingDetails)
        println "Request for " + certificateDN + " in process, Waiting for " + waitFor + " Seconds...."

        apTool.setOutputProperty("Ready", 'false')
        apTool.setOutputProperty("processingStatus", meta.ProcessingDetails.Status)
        apTool.setOutputProperty("processingStage",  String.valueOf(meta.ProcessingDetails.Stage))
        apTool.setOutputProperty("tppTicketDN",  String.valueOf(meta.ProcessingDetails.TicketDN))
        apTool.setOutputProperties()

        Thread.sleep(waitForInt * 1000);
      } else {
        println "Certificate Ready"
        certificateReady = true
        def retrieve = null
        try {
          retrieve = tpp.retrieveCertificate(tppURL, apikey, certificateDN, Format, IncludeChain, IncludePrivateKey, p12Password)
        } catch (Exception e) {
          println("ERROR ... 2")
          println(e)
          System.exit(-1)
        }
        def certificateData = retrieve.toString()
        def fileName = ""

        if (Format == "PKCS #12") {
          fileName = writeBase64EncodedCertToFile(x509Subject, certificateData, "p12")
        }

        println("filename : " + fileName)

        apTool.setOutputProperty("Filename", fileName)
        apTool.setOutputProperty("Ready", 'true')
        apTool.setOutputProperty("processingStatus", "N/A")
        apTool.setOutputProperty("processingStage", "N/A")
        apTool.setOutputProperties()

        break
      }

      apTool.setOutputProperty("approverGUID", meta.Approver[0])
      apTool.setOutputProperty("approverDN", tpp.guidToDN(tppURL, apikey, meta.Approver[0].minus("local:")).ObjectDN)
      apTool.setOutputProperty("contactGUID", meta.Contact[0])
      apTool.setOutputProperty("contactDN", tpp.guidToDN(tppURL, apikey, meta.Contact[0].minus("local:")).ObjectDN)

      apTool.setOutputProperties()

    }
    if (certificateReady == false) {
      System.exit(-1)
    } else {
      System.exit(0)
    }
  }

  def getCertificateStatus() {
    def tppURL = props['tppurl']
    def tppUser = props['tppUser']
    def tppPassword = props['tppPassword']
    def certificateDN = props['certificateDN']

    println("Parameters ")
    println("tppURL        " + tppURL)
    println("tppUser       " + tppUser)
    println("tppPassword   " + tppPassword)
    println("certificateDN " + certificateDN)

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
    }  catch (Exception e) {
      println("ERROR")
      System.exit(-1)
    }
  }

  def validateRemainingDays() {
    def tppURL = props['tppurl']
    def tppUser = props['tppUser']
    def tppPassword = props['tppPassword']
    def certificateDN = props['certificateDN']
    def failIflessThan = props['FailIfLessThan']

    println("Parameters ")
    println("tppURL                        : " + tppURL)
    println("tppUser                       : " + tppUser)
    println("tppPassword                   : " + tppPassword)
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
    def tppURL = props['tppurl']
    def tppUser = props['tppUser']
    def tppPassword = props['tppPassword']
    def certificateDN = props['certificateDN']
    def reasonCode = props['reasonCode']
    def commentText = props['comment']
    def disabled = props['disabled']

    if (disabled != null) {
      if (disabled != "true") {
        disabled = "false"
      }
    }

    println("Parameters ")
    println("tppURL        : " + tppURL)
    println("tppUser       : " + tppUser)
    println("tppPassword   : " + tppPassword)
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
    def tppURL = props['tppurl']
    def tppUser = props['tppUser']
    def tppPassword = props['tppPassword']
    def certificateDN = props['certificateDN']

    println("Parameters ")
    println("tppURL        : " + tppURL)
    println("tppUser       : " + tppUser)
    println("tppPassword   : " + tppPassword)
    println("certificateDN : " + certificateDN)

    def exitCode = 0

    def apikey = tpp.authenticate(tppURL, tppUser, tppPassword).APIKey

    try {
      def request = tpp.renewCertificate(tppURL, apikey, certificateDN)
      println request

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

    if (certificateData.contains("[")) {
      certificateData = certificateData.substring(1, certificateData.length())
    }
    if (certificateData.contains("]")) {
      certificateData = certificateData.substring(0, certificateData.length() - 1)
    }

    certificateData = certificateData.replaceAll("\\s","")

    def splitCertificate = certificateData.split(",")

    if (splitCertificate.size() > 0) {
      def certFound = 0
      def elementCounter = 0
      while ((certFound == 0) && (elementCounter < splitCertificate.size())) {
        if (splitCertificate[elementCounter].contains("CertificateData:")) {
          certFound = 1
          def certificate = splitCertificate[elementCounter].substring("CertificateData:".length(), splitCertificate[elementCounter].length())
          if (certificate.length() > 0) {

            // write the certificate to a file on the host

            byte[] decoded = certificate.decodeBase64()
            def decodedCertificate = new String(decoded)

            def splitLinesCert = decodedCertificate.split("\n")

            // decodedCertificate = ""

            // for (def lineCounter = 2; lineCounter < splitLinesCert.size(); lineCounter++) {
            //   decodedCertificate += splitLinesCert[lineCounter] + "\n"
            // }

            filename = filename + "." + extension

            new File(filename).bytes = certificate.decodeBase64()


            //def fileObject = new File(filename)

            //fileObject.withWriter('UTF-8') { writer ->
            //  writer.write(decodedCertificate)
            //}
          } else {
            println("Problem with the returned certificate data - CertificateData found but empty")
            println(certificateData)
          }
        }
        elementCounter++
      }
      if (certFound == 0) {
        println("Problem with the returned certificate data - unable to find the section 'CertificateData:'")
        println(certificateData)
      }
    } else {
      println("Problem with the returned certificate data - certificate doesn't have sections")
      println(certificateData)
    }
    return filename
  }
}
