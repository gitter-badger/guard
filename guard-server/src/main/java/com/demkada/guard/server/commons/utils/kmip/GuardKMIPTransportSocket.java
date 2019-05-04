package com.demkada.guard.server.commons.utils.kmip;

/*
 * Copyright 2019 DEMKADA.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author <a href="mailto:kad@demkada.com">Kad D.</a>
*/



import ch.ntb.inf.kmip.utils.KMIPUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class GuardKMIPTransportSocket implements GuardKMIPTransport {

    private static final Logger logger = LoggerFactory.getLogger(GuardKMIPTransportSocket.class);

    private SSLSocketFactory factory;
    private String url;
    private String keyStoreFileName;
    private String keyStorePassword;
    private String alias;
    private int port;

    public GuardKMIPTransportSocket() {
        logger.info("GuardKMIPTransportSocket initialized...");

        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((hostname, sslSession) -> hostname.equalsIgnoreCase(sslSession.getPeerHost()));
    }

    public ArrayList<Byte> send(ArrayList<Byte> al){
        try {
            KeyManager[] keyManagers = createKeyManagers(keyStoreFileName, keyStorePassword, alias);
            TrustManager[] trustManagers = createTrustManagers();
            factory = initItAll(keyManagers, trustManagers);
            return executePost(url, al, factory, port);
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyManagementException e) {
            logger.error("certs manager",e);
        }
        return new ArrayList<>();
    }


    private ArrayList<Byte> executePost(String targetURL, ArrayList<Byte> al, SSLSocketFactory sslSocketFactory, int port) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        HttpsURLConnection httpsConnection = null;

        try{
            KeyManager[] keyManagers = createKeyManagers(keyStoreFileName, keyStorePassword, alias);

            SSLSocket socket = createSslSocket(targetURL, port, keyManagers);
            DataOutputStream wr = new DataOutputStream(socket.getOutputStream());
            wr.write(KMIPUtils.toByteArray(al));

            wr.flush();

            InputStream dataInput = socket.getInputStream();

            ByteArrayOutputStream outputByte = new ByteArrayOutputStream();

            byte[] tab = new byte[8];

            dataInput.read(tab, 0, tab.length);


            byte[] tailleMessage = new byte[4];
            System.arraycopy(tab, 4, tailleMessage, 0, 4);

            int tailleReel =new BigInteger(tailleMessage).intValue();

            int tailleEncours = 0;
            outputByte.write(tab);

            byte[] tableauTemporaire = new byte[tailleReel];
            while( true ){

                dataInput.read(tableauTemporaire, 0, tableauTemporaire.length);
                outputByte.write(tableauTemporaire);
                tailleEncours = tableauTemporaire.length + tailleEncours;

                if( tailleEncours >= tailleReel ){
                    break;
                }
            }


            wr.close();

            socket.close();
            return KMIPUtils.convertByteArrayToArrayList(outputByte.toByteArray());



        }
        finally {
            if (httpsConnection != null) {
                httpsConnection.disconnect();
            }
        }
    }

    SSLSocket createSslSocket(String targetURL, int port, KeyManager[] keyManagers) throws NoSuchAlgorithmException, KeyManagementException, IOException {
        TrustManager[] trustManagers = createTrustManagers();

        SSLContext sslContext = initISSLContext(keyManagers, trustManagers);

        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        return (SSLSocket) socketFactory.createSocket(targetURL, port);
    }


    private SSLSocketFactory initItAll(KeyManager[] keyManagers, TrustManager[] trustManagers)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext context = initISSLContext(keyManagers, trustManagers);

        SSLSocketFactory ssl = context.getSocketFactory();

        return ssl;
    }


    private SSLContext initISSLContext(KeyManager[] keyManagers, TrustManager[] trustManagers)
            throws NoSuchAlgorithmException, KeyManagementException {

        Double version = Double.parseDouble(System.getProperty("java.specification.version"));

        SSLContext context;
        if (version > 1.6) {
            context = SSLContext.getInstance("TLSv1.2");
        } else {
            context = SSLContext.getInstance("TLSv1");
        }

        context.init(keyManagers, trustManagers, null);

        return context;
    }


    KeyManager[] createKeyManagers(String keyStoreFileName, String keyStorePassword, String alias) throws CertificateException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {

        KeyStore keyStore = null;
        try {
            InputStream inputStream = getInputStream(keyStoreFileName);
            //create keystore object, load it with keystorefile data
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(inputStream, keyStorePassword == null ? null : keyStorePassword.toCharArray());
        } catch (IOException e) {
            logger.error("Error while reading the KeyStore "+keyStoreFileName,e);
        }


        KeyManager[] managers;
        if (alias != null) {
            managers = new KeyManager[] {new GuardKMIPTransportSocket().new AliasKeyManager(keyStore, alias, keyStorePassword)};
        } else {
            //create keymanager factory and load the keystore object in it
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyStorePassword == null ? null : keyStorePassword.toCharArray());
            managers = keyManagerFactory.getKeyManagers();
        }
        return managers;
    }


    private  class Handler extends URLStreamHandler {
        /** The classloader to find resources from. */
        private final ClassLoader classLoader;

        public Handler() {
            this.classLoader = getClass().getClassLoader();
        }

        public Handler(ClassLoader classLoader) {
            this.classLoader = classLoader;
        }

        @Override
        protected URLConnection openConnection(URL u) throws IOException {

            URL resourceUrl=null;
            if (classLoader!=null) {
                resourceUrl  = classLoader.getResource(u.getPath());
            }else{
                resourceUrl = ClassLoader.getSystemClassLoader().getResource(u.getPath());
            }
            if (resourceUrl == null){
                logger.error("Cannot find the keystore ["+u.getFile()+"]}");
            }
            return resourceUrl.openConnection();
        }
    }


    private InputStream getInputStream(String keyStoreFileName) throws IOException {
        InputStream inputStream=null;
        if (new File(keyStoreFileName).exists()) {
            inputStream= new FileInputStream(keyStoreFileName);
        }else{
            inputStream = new URL(null,keyStoreFileName, new Handler(Thread.currentThread().getContextClassLoader())).openStream();
        }
        return inputStream;
    }

    private TrustManager[] createTrustManagers() {
        return new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };
    }


    public void setTargetHostname(String value) {
        this.url = value;
        logger.info("Connection to: "+value);
    }

    public void setKeyStoreLocation(String property) {
        keyStoreFileName = property;
    }

    public void setKeyStorePW(String property) {
        keyStorePassword = property;
    }

    public void setAlias(String alias) {

    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setKeystoreCertificateAlias(String aliasCertificateKeySecure) {
        this.alias = aliasCertificateKeySecure;
    }


    private class AliasKeyManager implements X509KeyManager {

        private KeyStore _ks;
        private String _alias;
        private String _password;

        public AliasKeyManager(KeyStore ks, String alias, String password) {
            _ks = ks;
            _alias = alias;
            _password = password;
        }

        public String chooseClientAlias(String[] str, Principal[] principal, Socket socket) {
            return _alias;
        }

        public String chooseServerAlias(String str, Principal[] principal, Socket socket) {
            return _alias;
        }

        public X509Certificate[] getCertificateChain(String alias) {

            java.security.cert.Certificate[] certificates = new java.security.cert.Certificate[0];
            try {
                certificates = this._ks.getCertificateChain(alias);

                if(certificates == null){
                    throw new Exception();
                }
                X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
                System.arraycopy(certificates, 0, x509Certificates, 0, certificates.length);
                return x509Certificates;
            }
            catch (Exception e) {
                logger.error ("Error while reading the keystore", e);
            }
            return null;
        }

        public String[] getClientAliases(String str, Principal[] principal) {
            return new String[] { _alias };
        }

        public PrivateKey getPrivateKey(String alias) {
            try {
                return (PrivateKey) _ks.getKey(alias, _password == null ? null : _password.toCharArray());
            } catch (Exception e) {
                logger.error ("Error while getting the private key", e);
            }
            return null;
        }

        public String[] getServerAliases(String str, Principal[] principal) {
            return new String[] { _alias };
        }

    }

}
