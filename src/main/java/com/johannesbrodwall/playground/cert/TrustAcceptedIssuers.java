package com.johannesbrodwall.playground.cert;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

public class TrustAcceptedIssuers implements X509TrustManager {

    private X509Certificate[] acceptedIssuers;

    public TrustAcceptedIssuers(X509Certificate... acceptedIssuers) {
        this.acceptedIssuers = acceptedIssuers;
    }

    private void checkCertificateTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain.length == 0) {
            throw new CertificateException("Certificate required, but none was given");
        }

        for (X509Certificate certificate : chain) {
            if (isTrustedIssuer(certificate)) {
                return;
            }
        }

        throw new CertificateException("Certificate not trusted");
    }

    private boolean isTrustedIssuer(X509Certificate certificate) throws CertificateException {
        certificate.checkValidity();
        for (X509Certificate acceptedIssuer : getAcceptedIssuers()) {
            if (certificate.equals(acceptedIssuer)) {
                return true;
            }
        }
        return false;
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
        return acceptedIssuers;
    }

}
