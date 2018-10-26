package com.johannesbrodwall.playground.cert;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

public class CertificateAndKey {

    private X509Certificate certificate;
    private KeyPair keyPair;

    public CertificateAndKey(X509Certificate certificate, KeyPair keyPair) {
        this.certificate = certificate;
        this.keyPair = keyPair;
    }

    public String getFingerprint() throws CertificateEncodingException {
        return fingerprint(certificate.getEncoded());
    }

    private static String fingerprint(byte[] encoded) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(encoded));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void writeToKeyStore(KeyStore keyStore, String alias) throws KeyStoreException {
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), "".toCharArray(),
                new Certificate[] { certificate });
    }

    public KeyManager[] getKeyManagers() throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        writeToKeyStore(keyStore, "clientKey");

        KeyManagerFactory managerFactory = KeyManagerFactory.getInstance("SunX509");
        managerFactory.init(keyStore, "".toCharArray());
        return managerFactory.getKeyManagers();
    }

    public X509Certificate getCertificate() {
        return certificate;
    }
}
