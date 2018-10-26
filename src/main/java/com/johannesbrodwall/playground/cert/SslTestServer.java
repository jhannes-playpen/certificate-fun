package com.johannesbrodwall.playground.cert;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
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
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.eclipse.jetty.util.thread.ScheduledExecutorScheduler;
import org.eclipse.jetty.webapp.WebAppContext;

public class SslTestServer {


    public static void main(String[] args) throws Exception {
        CertificateAndKey client = new CertificateBuilder()
                .withSubject("CN=Let's go")
                .withIssuer("CN=Johannes Authority")
                .generateKeyPair()
                .build();

        CertificateAndKey server = new CertificateBuilder()
                .withSubject("CN=localhost OU=yes!")
                .withIssuer("CN=Johannes Authority")
                .generateKeyPair()
                .build();

        SSLContext serverSslContext = createSslContext(server, Arrays.asList(client.getFingerprint()));
        SSLServerSocket serverSocket = (SSLServerSocket) serverSslContext.getServerSocketFactory().createServerSocket(0);

        Thread serverThread = new Thread(() -> runServerThread(serverSocket));
        serverThread.setDaemon(true);
        serverThread.start();

        QueuedThreadPool threadPool = new QueuedThreadPool();
        threadPool.setDaemon(true);

        Server jettyServer = new Server(threadPool);
        jettyServer.addBean(new ScheduledExecutorScheduler(null, true));
        jettyServer.addLifeCycleListener(Server.STOP_ON_FAILURE);

        WebAppContext handler = new WebAppContext(".", "/");
        handler.addServlet(new ServletHolder(new HelloWorldServlet()), "/hello");
        jettyServer.setHandler(handler);

        ServerConnector sslConnector = createSslConnector(jettyServer, serverSslContext, 10443);
        jettyServer.addConnector(sslConnector);


        jettyServer.start();

        SSLContext clientSslContext = createSslContext(client, Arrays.asList(server.getFingerprint()));
        try(SSLSocket socket = (SSLSocket) clientSslContext.getSocketFactory().createSocket("localhost", serverSocket.getLocalPort())) {
//            System.out.println("Certificate from server: " +
//                    ((X509Certificate) socket.getSession().getPeerCertificates()[0]).getSubjectDN());
//            String result = Util.inputStreamToString(socket.getInputStream());
//            System.out.println(result);
        }


        URL url = new URL("https://localhost:" + serverSocket.getLocalPort());
//        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
//        connection.setSSLSocketFactory(clientSslContext.getSocketFactory());
//        System.out.println(Util.inputStreamToString(connection.getInputStream()));

//        URL url2 = new URL("https://localhost:10443/hello");
//        HttpsURLConnection connection2 = (HttpsURLConnection) url2.openConnection();
//        connection2.setSSLSocketFactory(clientSslContext.getSocketFactory());
//        System.out.println(Util.inputStreamToString(connection2.getInputStream()));
    }

    public static ServerConnector createSslConnector(Server server, SSLContext sslContext, int port) throws GeneralSecurityException, IOException {
        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setSslContext(sslContext);
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

    private static SSLContext createSslContext(CertificateAndKey certificateAndKey, List<String> trustedFingerprints) throws GeneralSecurityException, IOException {
        SSLContext serverSslContext = SSLContext.getInstance("TLS");
        X509TrustManager tm = new TrustSpecificCertificates(trustedFingerprints);
        serverSslContext.init(certificateAndKey.getKeyManagers(), new TrustManager[] { tm }, null);
        return serverSslContext;
    }

    private static void runServerThread(SSLServerSocket serverSocket) {
        serverSocket.setWantClientAuth(true);
        serverSocket.setNeedClientAuth(true);
        while (true) {
            try (SSLSocket clientSocket = (SSLSocket) serverSocket.accept()) {
                try {
                    System.out.println("Certificate from client: " +
                            ((X509Certificate) clientSocket.getSession().getPeerCertificates()[0]).getSubjectDN());

                    String response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-length: 11\r\n\r\nHello world";
                    clientSocket.getOutputStream().write(response.getBytes());
                    clientSocket.getOutputStream().flush();

                    Thread.sleep(2000);
                } catch (Exception e) {
                    e.printStackTrace();
                    String response = "HTTP/1.1 400 OK\r\nConnection: close\r\nContent-length: " + e.toString().length() + "\r\n\r\n" + e;
                    clientSocket.getOutputStream().write(response.getBytes());
                    clientSocket.getOutputStream().flush();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}