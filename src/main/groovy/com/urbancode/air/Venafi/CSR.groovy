package com.urbancode.air.Venafi

import java.io.OutputStreamWriter
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Security

import javax.security.auth.x500.X500Principal

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMWriter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.X509Extension
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers

import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter

public class CSR {

  String algorithm
  Integer keySize
  String Signature
  String certificateCountry
  String certificateState
  String certificateCity
  String certificateOrganization
  String certificateOrganizationUnit
  String certificateWebSiteURL
  String certificateEmailAddress
  PrivateKey privateKey
  PublicKey publicKey

  public CSR(String algorithm, Integer keySize, String Signature) {
    this.algorithm = algorithm
    this.keySize = keySize
    this.Signature = Signature
   }

  public setCertificateCountry(String certificateCountry) { this.certificateCountry = certificateCountry }
  public setCertificateState(String certificateState) { this.certificateState = certificateState }
  public setCertificateCity(String certificateCity) { this.certificateCity = certificateCity }
  public setCertificateOrganization(String certificateOrganization) { this.certificateOrganization = certificateOrganization }
  public setCertificateOrganizationUnit(String certificateOrganizationUnit) { this.certificateOrganizationUnit = certificateOrganizationUnit }
  public setCertificateWebSiteURL(String certificateWebSiteURL) { this.certificateWebSiteURL = certificateWebSiteURL }
  public setCertificateEmailAddress(String certificateEmailAddress) { this.certificateEmailAddress = certificateEmailAddress }

  public getCertificateCountry() { return(certificateCountry) }
  public getCertificateState() { return(certificateState) }
  public getCertificateCity() { return(certificateCity) }
  public getCertificateOrganization() { return(certificateOrganization) }
  public getCertificateOrganizationUnit() { return(certificateOrganizationUnit) }
  public getCertificateWebSiteURL() { return(certificateWebSiteURL) }
  public getCertificateEmailAddress() { return(certificateEmailAddress) }

  public getCSRTOFile(String filename) {

    PKCS10CertificationRequest requestedCSR = generateCSR()

    OutputStreamWriter outputFile = new OutputStreamWriter(new FileOutputStream(filename))
    PEMWriter pemFileWriter = new PEMWriter(outputFile)
    pemFileWriter.writeObject(requestedCSR)
    pemFileWriter.close()

  }

  public String getCSR() {

    PKCS10CertificationRequest requestedCSR = generateCSR()

    StringWriter stringWriter = new StringWriter()

    PEMWriter pemWriter = new PEMWriter(stringWriter)
    pemWriter.writeObject(requestedCSR)
    pemWriter.flush()

    return(stringWriter.toString())
  }

	private PKCS10CertificationRequest generateCSR() throws Exception {

		// Provider bouncyCastleProvider = new BouncyCastleProvider()
		// Security.insertProviderAt(bouncyCastleProvider, 1)

    // Generate the key pair using a specific algorithm. Choices are :
    // DSA - Digital Signature Algorithm
    // RSA - RSA algorithm (Signature/Cipher)

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm)
		keyPairGenerator.initialize(keySize)
		KeyPair keyPair = keyPairGenerator.generateKeyPair()

    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    println("~~ Public & private key information  ~~")
    println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

		privateKey = keyPair.getPrivate()
		publicKey = keyPair.getPublic()

    // Signature options : SHA1withDSA, SHA1withRSA, SHA256withRSA

		JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(Signature)
    ContentSigner signer = jcaContentSignerBuilder.build(privateKey)

    String CSRContentText = "C=" + certificateCountry
    CSRContentText += ", ST=" + certificateState
    CSRContentText += ", L=" + certificateCity
    CSRContentText += ", O=" + certificateOrganization
    CSRContentText += ", OU=" + certificateOrganizationUnit
    CSRContentText += ", CN=" + certificateWebSiteURL
    CSRContentText += ", EMAILADDRESS=" + certificateEmailAddress

    X500Principal subject = new X500Principal(CSRContentText)
    PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey)
		PKCS10CertificationRequest request = builder.build(signer)

    return(request)
	}

  public void getPrivateKey(String fileName) {
    println("Private key format : " + privateKey.getFormat())

    Writer sw = new FileWriter(fileName)
    PEMWriter writer = new PEMWriter(sw)
    writer.writeObject(new PemObject("RSA PRIVATE KEY", privateKey.getEncoded()))
    writer.flush()

  }
  public void getPublicKey(String fileName) {
    println("Public  key format : " + publicKey.getFormat())

    Writer sw = new FileWriter(fileName)
    PEMWriter writer = new PEMWriter(sw)
    writer.writeObject(new PemObject("RSA PUBLIC KEY", publicKey.getEncoded()))
    writer.flush()

  }
}
