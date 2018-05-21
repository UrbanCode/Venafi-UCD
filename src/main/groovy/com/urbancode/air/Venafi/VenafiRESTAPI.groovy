package com.urbancode.air.Venafi

import groovy.json.JsonOutput
import groovyx.net.http.RESTClient

import java.security.Security

import static groovyx.net.http.ContentType.JSON

/**
 * Created by cbourne on 29/10/2016.
 */
public class VenafiRESTAPI {

    def authenticate(String url, String  user, String password) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()

      def request = client.post(path: '/vedsdk/authorize/',
              headers: ["content-type": "application/json"],
              body: [Username: user, Password: password],
              requestContentType: JSON)
      return request.data
    }

    def requestCertificate(String url, String  apiKey, String policyDn, String caDn, String x509Subject, String subjectAltNames) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()

      def request = client.post(path: '/vedsdk/Certificates/Request',
              headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
              body: [PolicyDN: policyDn, CADN: caDn, Subject: x509Subject, SubjectAltNames: subjectAltNames],
              requestContentType: JSON)
      return request.data
    }

    def readPolicyValue(String url, String  apiKey, String objectDn, String requiredAttributeName, String requiredClass) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()

       def request = client.post(path: '/vedsdk/config/ReadPolicy',
          headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
          body: [ObjectDN: objectDn, AttributeName: requiredAttributeName, Class: requiredClass],
          requestContentType: JSON)
      return request.data

    }

    def checkPolicy(String url, String  apiKey, String policyDn) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()

       def request = client.post(path: '/vedsdk/Certificates/CheckPolicy',
          headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
          body: [PolicyDN: policyDn],
          requestContentType: JSON)
      return request.data

    }

    def submitCertificateCSR(String url, String  apiKey, String policyDn, String CSR, String CertAuthorityDN, String objectName, String subjectAltNames) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()

      def request = client.post(path: '/vedsdk/Certificates/Request',
              headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
              body: [PolicyDN: policyDn, PKCS10: CSR, ObjectName: objectName, CADN: CertAuthorityDN, SubjectAltNames: subjectAltNames],
              requestContentType: JSON)

      return request.data
      println(request)

    }

    def retrieveCertificate(String url, String  apiKey, String certificateDn, String format, String includeChain, String includePrivateKey, String password, String friendlyName, String keystorePassword) {

      def client = new RESTClient(url)
      client.ignoreSSLIssues()

      def request = client.post(path: '/vedsdk/Certificates/Retrieve',
        headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
        body: [CertificateDN: certificateDn, Format: format, Password: password, IncludePrivateKey: includePrivateKey, IncludeChain: includeChain, FriendlyName: friendlyName, KeystorePassword: keystorePassword],
        requestContentType: JSON)
      return request.data
    }

    def revokeCertificate(String url, String  apiKey, String certificateDn, String reason, String comment, String disabled) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()

      if (comment == null) {
        comment = ""
      }

      def request = client.post(path: '/vedsdk/Certificates/Revoke',
              headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
              body: [CertificateDN: certificateDn, Reason: reason, Comment: comment, Disabled: disabled],
              requestContentType: JSON)
      return request.data

    }

    def renewCertificate(String url, String  apiKey, String certificateDn) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()

      def request = client.post(path: '/vedsdk/Certificates/Renew',
              headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
              body: [CertificateDN: certificateDn],
              requestContentType: JSON)
      return request.data

    }

    def guidToDN(String url, String apiKey, String guid) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()
      def request = client.post(path: '/vedsdk/Config/GuidToDN',
              headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
              body: [ObjectGUID: guid],
              requestContentType: JSON)
      return request.data
    }

    def dnToGUID(String url, String apiKey, String dn) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()
      def request = client.post(path: '/vedsdk/Config/DnToGuid',
              headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
              body: [ObjectDN: dn],
              requestContentType: JSON)
      return request.data
    }

    def certificateMeta(String url, String apiKey, String certificateDn) {
      def client = new RESTClient(url)
      client.ignoreSSLIssues()

      String guid = dnToGUID(url, apiKey, certificateDn).GUID

      def request = client.get(path: '/vedsdk/certificates/' + guid,
              headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
              requestContentType: JSON)
      return request.data
    }

    def retrieveCustomFieldData(String url, String  apiKey) {

      def client = new RESTClient(url)
      client.ignoreSSLIssues()

      def request = client.get(path: '/vedsdk/Metadata/Items',
        headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
        requestContentType: JSON)
      return request.data
    }

    def sendCustomFieldsToVenafiServer(String url, String  apiKey, String certificateDn, String customFieldData) {

      def client = new RESTClient(url)
      client.ignoreSSLIssues()

      def request = client.post(path: '/vedsdk/Metadata/Set',
        headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
        body: [DN: certificateDn, GuidData: customFieldData],
        requestContentType: JSON)
      return request.data
    }
}
