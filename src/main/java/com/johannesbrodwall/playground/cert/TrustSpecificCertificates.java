package com.johannesbrodwall.playground.cert;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.X509TrustManager;

public class TrustSpecificCertificates implements X509TrustManager {

    private List<String> trustedFingerprints;

    public TrustSpecificCertificates(List<String> trustedFingerprints) {
        this.trustedFingerprints = trustedFingerprints;
    }

    public TrustSpecificCertificates(String singleTrustedFingerprint) {
        this(Arrays.asList(singleTrustedFingerprint));
    }

    private void checkCertificateTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain.length == 0) {
            throw new CertificateException("Certificate required, but none was given");
        }

        String certificateFingerprint = fingerprint(chain[0].getEncoded());
        for (String trustedFingerprint : trustedFingerprints) {
            if (trustedFingerprint.equals(certificateFingerprint)) return;
        }

        throw new CertificateException("Certificate not in list of trusted certificates");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkCertificateTrusted(chain, authType);
    }


    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkCertificateTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    private String fingerprint(byte[] encoded) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(encoded));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
