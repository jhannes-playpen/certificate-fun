package com.johannesbrodwall.playground.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

@SuppressWarnings("restriction")
public class CertificateBuilder {

    private String subject;
    private String issuer;
    private KeyPair keyPair;
    private Date validFrom = new Date();
    private long validityDays = 100;

    public CertificateBuilder withSubject(String subject) {
        this.subject = subject;
        return this;
    }

    public CertificateBuilder withIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public CertificateBuilder generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        keyPair = generator.generateKeyPair();
        return this;
    }

    public CertificateAndKey build() throws GeneralSecurityException, IOException {
        X509Certificate certificate = createCertificate();
        return new CertificateAndKey(certificate, keyPair);
    }

    @SuppressWarnings("restriction")
    private X509Certificate createCertificate() throws GeneralSecurityException, IOException {
        X509CertInfo certInfo = new X509CertInfo();
        Date to = new Date(validFrom.getTime() + validityDays * 86400000l);
        CertificateValidity interval = new CertificateValidity(validFrom, to);
        AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
        certInfo.set(X509CertInfo.VALIDITY, interval);
        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
        certInfo.set(X509CertInfo.SUBJECT, new X500Name(subject));
        certInfo.set(X509CertInfo.ISSUER, new X500Name(issuer));
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));

        X509CertImpl certificateImpl = new X509CertImpl(certInfo);
        certificateImpl.sign(keyPair.getPrivate(), "SHA1withRSA");

        return certificateImpl;
    }

}
