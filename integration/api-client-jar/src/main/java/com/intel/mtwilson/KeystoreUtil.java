/*
 * Copyright (C) 2011-2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson;

import com.intel.mtwilson.crypto.CryptographyException;
import com.intel.mtwilson.crypto.RsaCredential;
import com.intel.mtwilson.crypto.RsaCredentialX509;
import com.intel.mtwilson.crypto.RsaUtil;
import com.intel.mtwilson.crypto.SimpleKeystore;
import com.intel.mtwilson.crypto.SslUtil;
import com.intel.mtwilson.datatypes.ApiClientCreateRequest;
import com.intel.mtwilson.io.FileResource;
import com.intel.mtwilson.io.Resource;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.configuration.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Java "keytool" command can be used to manage the contents of the KeyStore
 * independently. However, there is the additional problem of maintaining a list
 * of which "trusted" (identity only) certificate is authorized for what purpose
 * -- which the keystore does not provide. 
 * Option 1. Overload the "alias" to annotate the trusted purpose of each certificate
 * Option 2. Maintain a separate (signed) file with the list of trusted purpose of each certificate
 * 
 * For ApiClient usage, the SimpleKeystore class was written for Mt Wilson specific
 * needs. 
 * 
 * This class remains available so we don't break existing integrations but
 * it should not be used. 
 * 
 * Another alternative to this class for general use is Java's "keytool" command.
 *
 * Set the "mtwilson.api.keystore" property to point to this file (by default
 * keystore.jks) 
 * 
 * These methods are conveniences for using the KeyStore class but many of the
 * functionality needed for the api client are in the SimpleKeystore class.
 * 
 * @since 0.5.2
 * @author jbuhacoff
 */
public class KeystoreUtil {
    private static final Logger log = LoggerFactory.getLogger(KeystoreUtil.class);
    
    /**
     * 
     * @param keystoreIn
     * @param keystorePassword
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException 
     */
    public static KeyStore open(InputStream keystoreIn, String keystorePassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType()); // KeyStoreException. XXX TODO we need to implement AES-128 keystore encryption provider
        // load keystore
        try {
            ks.load(keystoreIn, keystorePassword.toCharArray()); // IOException, NoSuchAlgorithmException, CertificateException
        } finally {
            if (keystoreIn != null) {
                keystoreIn.close();
            }
        }
        return ks;
    }
    
    /**
     * 
     * @param config
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException 
     * @deprecated use the SimpleKeystore instead
     */
    public static KeyStore open(Configuration config) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        String filename = config.getString("mtwilson.api.keystore", "keystore.jks");
        String password = config.getString("mtwilson.api.keystore.password", "changeit");
        InputStream in;
        try {
            in = new FileInputStream(filename);
        }
        catch(FileNotFoundException e) {
            // not a file, try the classpath
            in = KeystoreUtil.class.getResourceAsStream(filename);
        }
        return open(in, password);
    }

    /**
     * 
     * @param keystore
     * @param certAlias
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableEntryException
     * @throws KeyStoreException
     * @throws CertificateEncodingException 
     */
    public static X509Certificate loadX509Certificate(KeyStore keystore, String certAlias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateEncodingException {
        // load the certificate
        KeyStore.TrustedCertificateEntry certEntry = (KeyStore.TrustedCertificateEntry)keystore.getEntry(certAlias, null);
        if( certEntry != null ) {
            Certificate myCertificate = certEntry.getTrustedCertificate();
            if( myCertificate instanceof X509Certificate ) { //if( "X.509".equals(myCertificate.getType()) ) {
                return (X509Certificate)myCertificate;
            }
            throw new IllegalArgumentException("Certificate is not X509: "+myCertificate.getType());
            //PublicKey myPublicKey = pkEntry.getCertificate().getPublicKey();
            //return new RsaCredential(myPrivateKey, myPublicKey);
        }
        throw new KeyStoreException("Cannot load certificate with alias: "+certAlias);
    }
    
    /**
     * 
     * @param keystore
     * @param keyAlias
     * @param keyPassword
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableEntryException
     * @throws KeyStoreException
     * @throws CertificateEncodingException 
     * @deprecated use the SimpleKeystore instead
     */
    public static RsaCredentialX509 loadX509(KeyStore keystore, String keyAlias, String keyPassword) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, CertificateEncodingException {
        // load the key pair
        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)keystore.getEntry(keyAlias, new KeyStore.PasswordProtection(keyPassword.toCharArray()));
        if( pkEntry != null ) {
            PrivateKey myPrivateKey = pkEntry.getPrivateKey();
            Certificate myCertificate = pkEntry.getCertificate();
            if( "X.509".equals(myCertificate.getType()) ) {
                return new RsaCredentialX509(myPrivateKey, (X509Certificate)myCertificate);
            }
            throw new IllegalArgumentException("Key has a certificate that is not X509: "+myCertificate.getType());
            //PublicKey myPublicKey = pkEntry.getCertificate().getPublicKey();
            //return new RsaCredential(myPrivateKey, myPublicKey);
        }
        
        // key pair not found
        throw new KeyStoreException("Cannot load key with alias: "+keyAlias);
        
    }

    /**
     * 
     * @param config
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableEntryException 
     * @deprecated use the SimpleKeystore instead
     */
    public static RsaCredential loadX509(Configuration config) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
        String keystore = config.getString("mtwilson.api.keystore", "keystore.jks");
        InputStream in;
        try {
            in = new FileInputStream(keystore);
        }
        catch(FileNotFoundException e) {
            // not a file, try the classpath
            in = KeystoreUtil.class.getResourceAsStream(keystore);
        }
        KeyStore ks = open(in, 
                config.getString("mtwilson.api.keystore.password", "changeit"));
        RsaCredential rsa = loadX509(ks,
                config.getString("mtwilson.api.key.alias", "mykey"),
                config.getString("mtwilson.api.key.password", "changeit"));
        return rsa;                
    }
    
    /**
     * The configuration must have the following properties:
     * 
     * Keystore relative filename, absolute filename, or location in classpath:
     * mtwilson.api.keystore=keystore.jks
     * 
     * Keystore password:
     * mtwilson.api.keystore.password=changeit
     * 
     * Private key alias:
     * mtwilson.api.key.alias=mykey
     * 
     * Private key password:
     * mtwilson.api.key.password=changeit
     * 
     * @param config
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableEntryException 
     * @deprecated use the SimpleKeystore instead
     */
    public static RsaCredential fromKeystore(Configuration config) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
        KeyStore keystore = open(config);
        return loadX509(keystore,
            config.getString("mtwilson.api.key.alias", "mykey"),
            config.getString("mtwilson.api.key.password", "changeit"));
    }
/*    
    public static void create(File file, String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = KeyStore.getInstance("JKS"); // KeyStoreException.  XXX TODO we need to supply type as a parameter because we will need to support multiple keystore types (Java default JKS and also our custom AES-128 keystore)
        keystore.load(null, null);
        keystore.store(new FileOutputStream(file), password.toCharArray()); // IOException, NoSuchAlgorithmException, CertificateException
    }
    
*/

    public static void save(KeyStore keystore, String password, File output) throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        keystore.store(new FileOutputStream(output), password.toCharArray()); // FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    }
    /*
    public static File save(KeyStore keystore, String password) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        File tmp = File.createTempFile("keystore", ".jks"); // IOException
        keystore.store(new FileOutputStream(tmp), password.toCharArray()); // KeyStoreException, NoSuchAlgorithmException, CertificateException
        return tmp;
    }
    * 
    
    * 
    */
    
    
    /**
     * Helper function for multi-user applications. This function creates a new
     * keystore with the given username and password, generates an RSA key and
     * X509 certificate for the user, registers the certificate with Mt Wilson,
     * and downloads the Mt Wilson SSL Certificate and SAML Signing Certificate
     * to the new keystore.
     * 
     * The path to the new keystore will be "directory/username.jks"
     * 
     * Implies Tls Policy TRUST_FIRST_CERTIFICATE
     * 
     * @param directory where the keystore should be saved
     * @param username arbitrary, needs to be unique only within the directory, should not contain any path-forming characters such as .. or slashes
     * @param password arbitrary
     * @param server URL to the Mt Wilson server like https://mtwilson.example.com:443
     * @param roles like new String[] { Role.Attestation.toString(), Role.Whitelist.toString() }
     * @return the new keystore
     * @throws Exception 
     */
    public static SimpleKeystore createUserInDirectory(File directory, String username, String password, URL server, String[] roles) throws IOException, ApiException, CryptographyException, ClientException {
        // XXX TODO instead of this basic check, should either use a regex to allow only specific character sets OR use an encoding such as url encoding (but make sure to also encode slashes) so that username can be arbitrary
        if( username.contains("..") || username.contains(File.separator) || username.contains(" ") ) { throw new IllegalArgumentException("Username must not include path-forming characters"); }
        File keystoreFile = new File(directory.getAbsoluteFile() + File.separator + username + ".jks");
        FileResource resource = new FileResource(keystoreFile);
        return createUserInResource(resource, username, password, server, roles);
    }

    /**
     * 
     * @param resource
     * @param username
     * @param password
     * @return
     * @throws CryptographyException
     * @throws IOException 
     */
    private static SimpleKeystore createUserKeystoreInResource(Resource resource, String username, String password) throws CryptographyException, IOException {
        try {
            // create the keystore and a new credential
            SimpleKeystore keystore = new SimpleKeystore(resource, password); // KeyManagementException
            KeyPair keypair = RsaUtil.generateRsaKeyPair(RsaUtil.MINIMUM_RSA_KEY_SIZE); // NoSuchAlgorithmException
            X509Certificate certificate = RsaUtil.generateX509Certificate(/*"CN="+*/username, keypair, RsaUtil.DEFAULT_RSA_KEY_EXPIRES_DAYS); // GeneralSecurityException
            keystore.addKeyPairX509(keypair.getPrivate(), certificate, username, password); // KeyManagementException
            keystore.save(); // KeyStoreException, IOException, CertificateException        
            return keystore;
        } 
        catch(KeyManagementException e) {
            throw new CryptographyException("Cannot create keystore", e);
        }
        catch(NoSuchAlgorithmException e) {
            throw new CryptographyException("Cannot create keystore", e);
        }
        catch(KeyStoreException e) {
            throw new CryptographyException("Cannot create keystore", e);
        }
        catch(CertificateException e) {
            throw new CryptographyException("Cannot create keystore", e);
        }
    }
    
    
    /**
     * Helper function for multi-user applications. This function creates a new
     * keystore with the given username and password, generates an RSA key and
     * X509 certificate for the user, registers the certificate with Mt Wilson,
     * and downloads the Mt Wilson SSL Certificate and SAML Signing Certificate
     * to the new keystore. Also any CA certificates available will be added
     * to the keystore. 
     * 
     * XXX TODO: there is no mechanism right now for the user to confirm the
     * server's TLS certificate fingerprint.  That is necessary for security.
     * The user could confirm after calling this function and before using
     * the keystore. Should we provide a helper method?
     * 
     * The underlying Resource implementation determines the location where the
     * keystore will be saved.
     * 
     * Implies Tls Policy TRUST_FIRST_CERTIFICATE
     * 
     * @param resource like FileResource or ByteArrayResource to which the keystore will be saved
     * @param username arbitrary, needs to be unique only within the resource container, and any restrictions on allowed characters are determined by the resource implmenetation
     * @param password arbitrary
     * @param server URL to the Mt Wilson server like https://mtwilson.example.com:443
     * @param roles like new String[] { Role.Attestation.toString(), Role.Whitelist.toString() }
     * @return the new keystore
     * @throws Exception 
     * @since 0.5.4
     */
    public static SimpleKeystore createUserInResource(Resource resource, String username, String password, URL server, String[] roles) throws IOException, ApiException, CryptographyException, ClientException {
        SimpleKeystore keystore = createUserKeystoreInResource(resource, username, password);
        if( "https".equals(server.getProtocol()) ) {
            SslUtil.addSslCertificatesToKeystore(keystore, server); //CryptographyException, IOException            
        }
        ApiClient c = null;
        try {
            // download server's ssl certificates and add them to the keystore
            // register the user with the server
            RsaCredentialX509 rsaCredential = keystore.getRsaCredentialX509(username, password); // CryptographyException, FileNotFoundException
            c = new ApiClient(server, rsaCredential, keystore, null); //ClientException
            ApiClientCreateRequest user = new ApiClientCreateRequest();
            user.setCertificate(rsaCredential.getCertificate().getEncoded()); //CertificateEncodingException
            user.setRoles(roles);
            c.register(user); //IOException
        }
        catch(IOException e) {
            throw new IOException("Cannot register user", e);
        }
        catch(Exception e) {
            throw new CryptographyException("Cannot register user", e);
        }
        
        // download root ca certs from the server
        try {
            Set<X509Certificate> cacerts = c.getRootCaCertificates();
            for(X509Certificate cacert : cacerts) {
                try {
                    log.info("Adding CA Certificate with alias {}, subject {}, fingerprint {}, from server {}", new String[] { cacert.getSubjectX500Principal().getName(), cacert.getSubjectX500Principal().getName(), DigestUtils.shaHex(cacert.getEncoded()), server.getHost() });
                    keystore.addTrustedCaCertificate(cacert, cacert.getSubjectX500Principal().getName()); // XXX TODO need error checking on:  1) is the name a valid alias or does it need munging, 2) is there already a different cert with that alias in the keystore
                }
                catch(Exception e) {
                    log.error(e.toString());
                }
            }            
        }
        catch(Exception e) {
            log.error(e.toString());
        }
        
        // download privacy ca certs from server
        try {
            Set<X509Certificate> cacerts = c.getPrivacyCaCertificates();
            for(X509Certificate cacert : cacerts) {
                try {
                    log.info("Adding Privacy CA Certificate with alias {}, subject {}, fingerprint {}, from server {}", new String[] { cacert.getSubjectX500Principal().getName(), cacert.getSubjectX500Principal().getName(), DigestUtils.shaHex(cacert.getEncoded()), server.getHost() });
                    keystore.addTrustedCaCertificate(cacert, cacert.getSubjectX500Principal().getName()); // XXX TODO need error checking on:  1) is the name a valid alias or does it need munging, 2) is there already a different cert with that alias in the keystore
                }
                catch(Exception e) {
                    log.error(e.toString());
                }
            }            
        }
        catch(Exception e) {
            log.error(e.toString());
        }
        
        // download saml ca certs from server
        try {
            Set<X509Certificate> cacerts = c.getSamlCertificates();
            for(X509Certificate cert : cacerts) {
                try {
                    if( cert.getBasicConstraints() == -1 ) {  // -1 indicates the certificate is not a CA cert; so we add it as the saml cert
                        keystore.addTrustedSamlCertificate(cert, server.getHost());
                        log.info("Added SAML Certificate with alias {}, subject {}, fingerprint {}, from server {}", new String[] { cert.getSubjectX500Principal().getName(), cert.getSubjectX500Principal().getName(), DigestUtils.shaHex(cert.getEncoded()), server.getHost() });
                    }
                    else {
                        keystore.addTrustedCaCertificate(cert, cert.getSubjectX500Principal().getName()); // XXX TODO need error checking on:  1) is the name a valid alias or does it need munging, 2) is there already a different cert with that alias in the keystore
                        log.info("Added SAML CA Certificate with alias {}, subject {}, fingerprint {}, from server {}", new String[] { cert.getSubjectX500Principal().getName(), cert.getSubjectX500Principal().getName(), DigestUtils.shaHex(cert.getEncoded()), server.getHost() });
                    }
                }
                catch(Exception e) {
                    log.error(e.toString());
                }
            }            
        }
        catch(Exception e) {
            log.error(e.toString());
        }
        
        return keystore;
    }
    
    /**
     * Helper function for multi-user applications. This function loads the
     * keystore using the provided username and password, and creates an 
     * ApiClient object using the credentials in the keystore. 
     * 
     * @param directory where the keystore is located
     * @param username the keystore filename (excluding the .jks extension)
     * @param password that was set when the keystore was created
     * @param server URL to the Mt Wilson server like https://mtwilson.example.com:443
     * @return an ApiClient object configured with the credentials in the keystore
     * @throws Exception 
     */
    public static ApiClient clientForUserInDirectory(File directory, String username, String password, URL server) throws Exception {
        if( username.contains("..") || username.contains(File.separator) || username.contains(" ") ) { throw new IllegalArgumentException("Username must not include path-forming characters"); }
        File keystoreFile = new File(directory.getAbsoluteFile() + File.separator + username + ".jks");
        FileResource resource = new FileResource(keystoreFile);
        return clientForUserInResource(resource, username, password, server);
    }
    
    /**
     * Helper function for multi-user applications. This function loads the
     * keystore using the provided username and password, and creates an 
     * ApiClient object using the credentials in the keystore. 
     * 
     * @param resource like FileResource or ByteArrayResource from which the keystore will be loaded
     * @param username the keystore filename (excluding the .jks extension)
     * @param password that was set when the keystore was created
     * @param server URL to the Mt Wilson server like https://mtwilson.example.com:443
     * @return an ApiClient object configured with the credentials in the keystore
     * @throws Exception 
     * @since 0.5.4
     */
    public static ApiClient clientForUserInResource(Resource resource, String username, String password, URL server) throws Exception {
        SimpleKeystore keystore = new SimpleKeystore(resource, password);
        RsaCredentialX509 rsaCredential = keystore.getRsaCredentialX509(username, password);
        ApiClient c = new ApiClient(server, rsaCredential, keystore, null);
        return c;        
    }
    
    
    
}
