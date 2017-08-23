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

        // Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        def client = new RESTClient(url)
        client.ignoreSSLIssues()

        def request = client.post(path: '/vedsdk/authorize/',
                headers: ["content-type": "application/json"],
                body: [Username: user, Password: password],
                requestContentType: JSON)
        return request.data

    }

    def requestCertificate(String url, String  apiKey, String policyDn, String caDn, String x509Subject) {

        // Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        def client = new RESTClient(url)
        client.ignoreSSLIssues()

        def request = client.post(path: '/vedsdk/Certificates/Request',
                headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
                body: [PolicyDN: policyDn, CADN: caDn, Subject: x509Subject],
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

        //  objectDn = "\\VED\\Policy\\DevOps_Workshop\\Test1"
        //  requiredAttributeName = "Description"
        //  def request = client.post(path: '/vedsdk/config/ReadEffectivePolicy',
        //        headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
        //        body: [ObjectDN: objectDn, AttributeName: requiredAttributeName],
        //        requestContentType: JSON)
        return request.data

    }

    def requestCertificateCSR(String url, String  apiKey, String policyDn, String CSR) {

        // Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        def client = new RESTClient(url)
        client.ignoreSSLIssues()

        def request = client.post(path: '/vedsdk/Certificates/Request',
                headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
                body: [PolicyDN: policyDn, PKCS10: CSR],
                requestContentType: JSON)

        println(request.body)
        return request.data

        println(request)

    }

    def retrieveCertificate(String url, String  apiKey, String certificateDn, String format, String includeChain, String includePrivateKey, String password) {

        // Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        def client = new RESTClient(url)
        client.ignoreSSLIssues()

        def request = client.post(path: '/vedsdk/Certificates/Retrieve',
                headers: ["content-type": "application/json", "X-Venafi-Api-Key": apiKey],
                body: [CertificateDN: certificateDn, Format: format, IncludeChain: includeChain, IncludePrivateKey: includePrivateKey, Password: password],
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

}
