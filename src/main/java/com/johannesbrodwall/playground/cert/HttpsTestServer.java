package com.johannesbrodwall.playground.cert;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.webapp.WebAppContext;

public class HttpsTestServer {

    private CertificateAndKey authority;
    private CertificateAndKey client;
    private CertificateAndKey server;

    public static void main(String[] args) throws Exception {
        HttpsTestServer server = new HttpsTestServer();
        server.run(args);
    }

    public void run(String[] args) throws Exception {
        generateKeyPair();
        startServer();
        makeHttpRequest();
    }

    private void makeHttpRequest() throws IOException, GeneralSecurityException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://localhost:10443/hello").openConnection();

        SSLContext sslContext = createSslContext(client, Arrays.asList(server.getFingerprint()));
        connection.setSSLSocketFactory(sslContext.getSocketFactory());

        int responseCode = connection.getResponseCode();
        System.out.println("response: " + responseCode);
        System.out.println(Util.inputStreamToString(connection.getInputStream()));
    }

    private static SSLContext createSslContext(CertificateAndKey certificateAndKey, List<String> trustedFingerprints) throws GeneralSecurityException, IOException {
        SSLContext serverSslContext = SSLContext.getInstance("TLS");
        X509TrustManager tm = new TrustSpecificCertificates(trustedFingerprints);
        serverSslContext.init(certificateAndKey.getKeyManagers(), new TrustManager[] { tm }, null);
        return serverSslContext;
    }


    public void startServer() throws Exception {
        Server server = createServer();
        server.start();
    }

    public Server createServer() throws GeneralSecurityException, IOException {
        Server server = new Server();
        server.addLifeCycleListener(Server.STOP_ON_FAILURE);

        ServerConnector connector = new ServerConnector(server);
        connector.setPort(10080);
        server.addConnector(connector);

        ServerConnector sslConnector = createSslConnector(server, 10443);
        server.addConnector(sslConnector);

        WebAppContext handler = new WebAppContext(".", "/");
        handler.addServlet(new ServletHolder(new HelloWorldServlet()), "/hello");
        server.setHandler(handler);
        return server;
    }

    public ServerConnector createSslConnector(Server server, int port) throws GeneralSecurityException, IOException {
        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setSslContext(createSslContext());
        sslContextFactory.setWantClientAuth(true);
        sslContextFactory.setNeedClientAuth(true);
        SslConnectionFactory sslConnectionFactory = new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.asString());
        ServerConnector sslConnector = new ServerConnector(server, sslConnectionFactory);
        sslConnector.addIfAbsentConnectionFactory(sslConnectionFactory);
        HttpConfiguration httpConfig = new HttpConfiguration();
        httpConfig.addCustomizer(new SecureRequestCustomizer());
        sslConnector.addIfAbsentConnectionFactory(new HttpConnectionFactory(httpConfig));
        sslConnector.setPort(port);
        return sslConnector;
    }

    public SSLContext createSslContext() throws GeneralSecurityException, IOException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(server.getKeyManagers(),
                new TrustManager[] { new TrustAcceptedIssuers(client.getCertificate()) },
                null);
        return sslContext;
    }

    private void generateKeyPair() throws GeneralSecurityException, IOException {
        authority = new CertificateBuilder()
            .withSubject("CN=Johannes Authority")
            .withIssuer("CN=Johannes Authority")
            .generateKeyPair()
            .build();


        client = new CertificateBuilder()
                .withSubject("CN=my-fine-client")
                .withIssuer("CN=Johannes Authority")
                .generateKeyPair()
                .build();

        server = new CertificateBuilder()
                .withSubject("CN=localhost")
                .withIssuer("CN=Johannes Authority")
                .generateKeyPair()
                .build();
    }
}
